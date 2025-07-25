# QRSMS Sender Provider

**Not verify in Quarkus 19.0.1**

```sh
cp target/providers/keycloak-phone-provider.jar ${KEYCLOAK_HOME}/providers/
cp target/providers/keycloak-phone-provider.resources.jar ${KEYCLOAK_HOME}/providers/
cp target/providers/keycloak-sms-provider-qrsms.jar ${KEYCLOAK_HOME}/providers/


${KEYCLOAK_HOME}/bin/kc.sh build

# username and password is required
# url is optional, defaults to http://localhost
# from is optional
# encoding is optional, can be set to UNICODE
# routing-group is optional

${KEYCLOAK_HOME}/bin/kc.sh start --spi-phone-default-service=qrsms \
  --spi-message-sender-service-qrsms-url=${url} \
  --spi-message-sender-service-qrsms-api-key=${api_key}
```
