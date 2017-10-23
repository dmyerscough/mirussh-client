MiruSSH Client
==============

The MiruSSH client automatically generates an SSH key pair and have the public key signed by the certificate authority.
Once the public keyhas been signed, the client loads the SSH key pair and the signed certificate into the SSH agent.

The MiruSSH client relies on a configuration file (`~/.mirussh`), which contains the following:

```yaml
endpoint: "127.0.0.1:8080"
token: "XXXX"
```

The token is generated in the MiruSSH UI.
