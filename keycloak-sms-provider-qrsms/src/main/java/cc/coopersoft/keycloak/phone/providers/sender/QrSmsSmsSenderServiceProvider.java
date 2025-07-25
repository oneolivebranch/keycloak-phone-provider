package cc.coopersoft.keycloak.phone.providers.sender;

import cc.coopersoft.keycloak.phone.providers.exception.MessageSendException;
import cc.coopersoft.keycloak.phone.providers.spi.FullSmsSenderAbstractService;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;

public class QrSmsSmsSenderServiceProvider extends FullSmsSenderAbstractService {

    public static final String CONFIG_API_SERVER = "url";
    public static final String CONFIG_API_KEY = "api-key";

    private static final Logger logger = Logger.getLogger(QrSmsSmsSenderServiceProvider.class);

    private final String url;
    private final String apiKey;

    QrSmsSmsSenderServiceProvider(Scope config, KeycloakSession session) {
        super(session);

        String configUrl = config.get(CONFIG_API_SERVER);
        this.url = configUrl != null ? configUrl : "http://localhost";
        this.apiKey = config.get(CONFIG_API_KEY);
    }

    @Override
    public void sendMessage(String phoneNumber, String message) throws MessageSendException {
        HttpClient httpclient = HttpClients.createDefault();
        SimpleHttp req = SimpleHttp.doGet(url + "/api/send-sms?token=" + this.apiKey + "&to=" + phoneNumber + "&text=" + message, httpclient);

        try {
            SimpleHttp.Response res = req.asResponse();
            if (res.getStatus() >= 200 || res.getStatus() <= 299) {
                logger.debugv("Sent SMS to {0} with contents: {1}. Server responded with: {2}", phoneNumber, message,
                        res.asString());
            } else {
                logger.errorv("Failed to deliver SMS to {0} with contents: {1}. Server responded with: {2}",
                        phoneNumber,
                        message, res.asString());
                throw new MessageSendException("Bulksms API responded with an error.", new Exception(res.asString()));
            }
        } catch (IOException ex) {
            logger.errorv(ex,
                    "Failed to send SMS to {0} with contents: {1}. An IOException occurred while communicating with SMS service {0}.",
                    phoneNumber, message, url);
            throw new MessageSendException("Error while communicating with Bulksms API.", ex);
        }
    }

    @Override
    public void close() {
    }
}
