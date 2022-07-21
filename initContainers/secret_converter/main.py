from kubernetes import client, config
import json
import base64


def main():
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    namespace = 'mlrun'
    secret_name = 'registry-credentials'
    username = ''
    password = ''
    user_registry = ''

    # Read the secret
    base64_data = ''
    secret = v1.read_namespaced_secret(secret_name, namespace)
    try:
        base64_data = secret.data['.dockercfg']
    except KeyError:
        try:
            base64_data = secret.data['.dockerconfigjson']
            print('Secret is already in required format - nothing to do.')
            exit(0)
        except KeyError:
            print('Required keys not found in secret - secret is invalid.')
            exit(0)

    base64_bytes = base64_data.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')

    # Extract the data
    jmessage = json.loads(message)
    for registry, auth in jmessage['auths'].items():
        user_registry = registry
        for k, v in auth.items():
            if k == 'username':
                username = v
            if k == 'password':
                password = v

    # Encode auth
    bytes_to_encode = ':'.join([username, password]).encode('ascii')
    base64_bytes = base64.b64encode(bytes_to_encode)
    base64_auth = base64_bytes.decode('ascii')

    # Craft payload
    payload = {
                "auths": {
                            user_registry: {
                                    "auth": base64_auth
                            }
                }
    }

    js_payload = json.dumps(payload)

    # Prepare new secret
    metadata = {'name': secret_name, 'namespace': namespace}
    new_secret = client.V1Secret(api_version='v1',
                                 data=None,
                                 kind='Secret',
                                 metadata=metadata,
                                 string_data={'.dockerconfigjson': js_payload},
                                 type='kubernetes.io/dockerconfigjson'
                                 )

    # Replace secret
    v1.delete_namespaced_secret(secret_name, namespace)
    v1.create_namespaced_secret(namespace, new_secret)


if __name__ == '__main__':
    main()
