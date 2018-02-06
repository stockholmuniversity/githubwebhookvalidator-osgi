package se.su.it.osgi.githubwebhookvalidator;

import org.apache.camel.Message;
import org.apache.camel.PropertyInject;

import org.apache.camel.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.codec.digest.HmacUtils;

public class HmacValidator {

    private static final Logger LOG = LoggerFactory.getLogger(HmacValidator.class);

    private String secret;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public void validate(Message message) throws ValidationException {

        Object body = message.getBody();
        String signature = message.getHeader("X-Hub-Signature", String.class);
        LOG.debug("X-Hub-Signature: {}", signature);

	String hmac = HmacUtils.hmacSha1Hex(secret, message.getBody(String.class));
        String gitHubStyleHmac = "sha1=" + hmac;
        LOG.debug("Calculated HMAC: {}", gitHubStyleHmac);

        if (!signature.equals(gitHubStyleHmac)) {
            throw new ValidationException(message.getExchange(), "Incoming message can't be verified - is Github configured correctly?.");
        }
    }
}
