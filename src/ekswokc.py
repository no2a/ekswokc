# Copyright 2022 Arata Notsu
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Get a kubernetes client without kubeconfig and authenticator (`aws eks get-token` or aws-iam-authenticator)
Most of code here from
https://raw.githubusercontent.com/aws/aws-cli/2.7.26/awscli/customizations/eks/get_token.py
and
https://raw.githubusercontent.com/kubernetes-client/python/v24.2.0/examples/remote_cluster.py
# Usage example
import kubernetes
region = 'us-west-2'
cluster_name = 'my-cluster'
role_arn = None
api_client = get_kubernetes_client(region, cluster_name, role_arn)
v1 = kubernetes.client.CoreV1Api(api_client)
ret = v1.list_pod_for_all_namespaces(watch=False)
for i in ret.items:
    print("%s\t%s\t%s" %
        (i.status.pod_ip, i.metadata.namespace, i.metadata.name))
"""

import base64
import json
import logging
import os
import sys
from datetime import datetime, timedelta

import botocore
import botocore.session
import boto3
from kubernetes import client
from kubernetes.config.kube_config import FileOrData


LOG = logging.getLogger(__name__)

ALPHA_API = "client.authentication.k8s.io/v1alpha1"
BETA_API = "client.authentication.k8s.io/v1beta1"
V1_API = "client.authentication.k8s.io/v1"

FULLY_SUPPORTED_API_VERSIONS = [
    V1_API,
    BETA_API,
]
DEPRECATED_API_VERSIONS = [
    ALPHA_API,
]

ERROR_MSG_TPL = (
    "{0} KUBERNETES_EXEC_INFO, defaulting to {1}. This is likely a "
    "bug in your Kubernetes client. Please update your Kubernetes "
    "client."
)
UNRECOGNIZED_MSG_TPL = (
    "Unrecognized API version in KUBERNETES_EXEC_INFO, defaulting to "
    "{0}. This is likely due to an outdated AWS "
    "CLI. Please update your AWS CLI."
)
DEPRECATION_MSG_TPL = (
    "Kubeconfig user entry is using deprecated API version {0}. Run "
    "'aws eks update-kubeconfig' to update."
)

# Presigned url timeout in seconds
URL_TIMEOUT = 60

TOKEN_EXPIRATION_MINS = 14

TOKEN_PREFIX = 'k8s-aws-v1.'

CLUSTER_NAME_HEADER = 'x-k8s-aws-id'


def _get_expiration_time():
    token_expiration = datetime.utcnow() + timedelta(
        minutes=TOKEN_EXPIRATION_MINS
    )
    return token_expiration.strftime('%Y-%m-%dT%H:%M:%SZ')


def _get_token(session, region, cluster_name, role_arn):
    client_factory = STSClientFactory(session)
    sts_client = client_factory.get_sts_client(
        region_name=region, role_arn=role_arn
    )
    token = TokenGenerator(sts_client).get_token(cluster_name)

    # By default STS signs the url for 15 minutes so we are creating a
    # rfc3339 timestamp with expiration in 14 minutes as part of the token, which
    # is used by some clients (client-go) who will refresh the token after 14 mins
    token_expiration = _get_expiration_time()

    return {
        "kind": "ExecCredential",
        "apiVersion": _discover_api_version(),
        "spec": {},
        "status": {
            "expirationTimestamp": token_expiration,
            "token": token,
        },
    }


def _discover_api_version():
    """
    Parses the KUBERNETES_EXEC_INFO environment variable and returns the
    API version. If the environment variable is malformed or invalid,
    return the v1beta1 response and print a message to stderr.

    If the v1alpha1 API is specified explicitly, a message is printed to
    stderr with instructions to update.

    :return: The client authentication API version
    :rtype: string
    """
    # At the time Kubernetes v1.29 is released upstream (approx Dec 2023),
    # "v1beta1" will be removed. At or around that time, EKS will likely
    # support v1.22 through v1.28, in which client API version "v1beta1"
    # will be supported by all EKS versions.
    fallback_api_version = BETA_API

    error_prefixes = {
        "error": "Error parsing",
        "empty": "Empty",
    }

    exec_info_raw = os.environ.get("KUBERNETES_EXEC_INFO", "")
    if not exec_info_raw:
        # All kube clients should be setting this, but client-go clients
        # (kubectl, kubelet, etc) < 1.20 were not setting this if the API
        # version defined in the kubeconfig was not v1alpha1.
        #
        # This was changed in kubernetes/kubernetes#95489 so that
        # KUBERNETES_EXEC_INFO is always provided
        return fallback_api_version
    try:
        exec_info = json.loads(exec_info_raw)
    except json.JSONDecodeError:
        # The environment variable was malformed
        LOG.warning(ERROR_MSG_TPL.format(error_prefixes["error"], fallback_api_version))
        return fallback_api_version

    api_version_raw = exec_info.get("apiVersion")
    if api_version_raw in FULLY_SUPPORTED_API_VERSIONS:
        return api_version_raw
    elif api_version_raw in DEPRECATED_API_VERSIONS:
        LOG.warning(DEPRECATION_MSG_TPL.format(api_version_raw))
        return api_version_raw
    else:
        LOG.warning(UNRECOGNIZED_MSG_TPL.format(fallback_api_version))
        return fallback_api_version


class TokenGenerator(object):
    def __init__(self, sts_client):
        self._sts_client = sts_client

    def get_token(self, cluster_name):
        """Generate a presigned url token to pass to kubectl."""
        url = self._get_presigned_url(cluster_name)
        token = TOKEN_PREFIX + base64.urlsafe_b64encode(
            url.encode('utf-8')
        ).decode('utf-8').rstrip('=')
        return token

    def _get_presigned_url(self, cluster_name):
        return self._sts_client.generate_presigned_url(
            'get_caller_identity',
            Params={'ClusterName': cluster_name},
            ExpiresIn=URL_TIMEOUT,
            HttpMethod='GET',
        )


class STSClientFactory(object):
    def __init__(self, session):
        self._session = session

    def get_sts_client(self, region_name=None, role_arn=None):
        client_kwargs = {'region_name': region_name}
        if role_arn is not None:
            creds = self._get_role_credentials(region_name, role_arn)
            client_kwargs['aws_access_key_id'] = creds['AccessKeyId']
            client_kwargs['aws_secret_access_key'] = creds['SecretAccessKey']
            client_kwargs['aws_session_token'] = creds['SessionToken']
        sts = self._session.create_client('sts', **client_kwargs)
        self._register_cluster_name_handlers(sts)
        return sts

    def _get_role_credentials(self, region_name, role_arn):
        sts = self._session.create_client('sts', region_name)
        return sts.assume_role(
            RoleArn=role_arn, RoleSessionName='EKSGetTokenAuth'
        )['Credentials']

    def _register_cluster_name_handlers(self, sts_client):
        sts_client.meta.events.register(
            'provide-client-params.sts.GetCallerIdentity',
            self._retrieve_cluster_name,
        )
        sts_client.meta.events.register(
            'before-sign.sts.GetCallerIdentity',
            self._inject_cluster_name_header,
        )

    def _retrieve_cluster_name(self, params, context, **kwargs):
        if 'ClusterName' in params:
            context['eks_cluster'] = params.pop('ClusterName')

    def _inject_cluster_name_header(self, request, **kwargs):
        if 'eks_cluster' in request.context:
            request.headers[CLUSTER_NAME_HEADER] = request.context[
                'eks_cluster'
            ]


def get_token(region, cluster_name, role_arn, session=None):
    if not session:
        session = botocore.session.Session()
    return _get_token(session, region, cluster_name, role_arn)


def _get_kubernetes_client(token, host, ssl_ca_cert):
    c = client.Configuration()
    c.host = host
    c.verify_ssl = True
    c.ssl_ca_cert = ssl_ca_cert
    c.api_key = {"authorization": "Bearer " + token}
    return client.ApiClient(c)


def get_kubernetes_client(region, cluster_name, role_arn):
    eks = boto3.client('eks')
    c = eks.describe_cluster(name=cluster_name)['cluster']
    ca = c['certificateAuthority']
    ssl_ca_cert = FileOrData(obj=ca, file_key_name=None, data_key_name='data').as_file()
    t = get_token(region=region, cluster_name=cluster_name, role_arn=role_arn)
    return _get_kubernetes_client(t['status']['token'], c['endpoint'], ssl_ca_cert)
