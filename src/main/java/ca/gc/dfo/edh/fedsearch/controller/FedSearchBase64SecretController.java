package ca.gc.dfo.edh.fedsearch.controller;



import ca.gc.dfo.edh.fedsearch.services.VaultService;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.text.ParseException;

@RestController
@RequestMapping("/api/fedsearch/base64secret")
public class FedSearchBase64SecretController implements EnvironmentAware {

    final Logger logger = LoggerFactory.getLogger(FedSearchBase64SecretController.class);

    private final VaultService vaultService;
    private String kvv2FedSearchBase64SecretRoot;
    private String kvv2FedSearchBase64SecretPath;


    @Autowired
    public FedSearchBase64SecretController(VaultService vaultService) {
        this.vaultService = vaultService;
    }

    @PostMapping(path = "/{app}")
    public Mono<String> createBase64Secret(@PathVariable String app, @RequestBody FedSearchBase64SecretRequest secret, @RequestHeader("Authorization") String token) {

        String bearerToken = token.substring(7);
        String sub = getSubFromBearerToken(bearerToken);
        if (sub == null) {
            return Mono.error(new Exception("Error parsing JWT or sub"));
        }

        vaultService.JWTLogin(bearerToken);
        vaultService.writeBase64Secret(kvv2FedSearchBase64SecretRoot, kvv2FedSearchBase64SecretPath.replace("subholder", sub).concat("/").concat(app), secret.getValue());
        logger.info("User {} create Base64 secret. App: {}", sub, app);
        return Mono.just(secret.getValue());
    }

    @GetMapping(path = "/{app}")
    public Mono<String> getBase64Secret(@PathVariable String app,  @RequestHeader("Authorization") String token) {
        String bearerToken = token.substring(7);
        String sub = getSubFromBearerToken(bearerToken);
        if (sub == null) {
            return Mono.error(new Exception("Error parsing JWT or sub"));
        }

        vaultService.JWTLogin(bearerToken);
        String secret = vaultService.readBase64Secret(kvv2FedSearchBase64SecretRoot, kvv2FedSearchBase64SecretPath.replace("subholder", sub).concat("/").concat(app));
        if (secret == null) {
            logger.info("User {} does not have Base64 secret for App: {} ", sub, app);
            return Mono.empty();
        }
        logger.info("User {} get Base64 secret. App: {}", sub, app);
        return Mono.just(secret);
    }



    @PutMapping(path = "/{app}")
    public Mono<String> updateBase64Secret( @PathVariable String app, @RequestHeader("Authorization") String token, @RequestBody FedSearchBase64SecretRequest secret) {
        String bearerToken = token.substring(7);
        String sub = getSubFromBearerToken(bearerToken);
        if (sub == null) {
            return Mono.error(new Exception("Error parsing JWT or sub"));
        }

        vaultService.JWTLogin(bearerToken);
        vaultService.updateBase64Secret(kvv2FedSearchBase64SecretRoot, kvv2FedSearchBase64SecretPath.replace("subholder", sub).concat("/").concat(app), secret.getValue());
        logger.info("User {} update Base64 secret. App: {}", sub, app);
        return Mono.just(secret.getValue());
    }

    @DeleteMapping(path = "/{app}")
    public Mono<Void> deleteBase64Secret( @PathVariable String app, @RequestHeader("Authorization") String token) {
        String bearerToken = token.substring(7);
        String sub = getSubFromBearerToken(bearerToken);
        if (sub == null) {
            return Mono.error(new Exception("Error parsing JWT or sub"));
        }

        vaultService.JWTLogin(bearerToken);
        vaultService.deleteBase64Secret(kvv2FedSearchBase64SecretRoot, kvv2FedSearchBase64SecretPath.replace("subholder", sub).concat("/").concat(app));
        logger.info("User {} delete Base64 secret. App: {}", sub, app);
        return Mono.empty();
    }

    private String getSubFromBearerToken(String bearerToken) {
        JWT jwt;
        String sub;
        try{
            jwt = JWTParser.parse(bearerToken);
            sub = jwt.getJWTClaimsSet().getSubject();
        }catch ( ParseException e){
            logger.warn("Error parsing JWT or sub", e);
            return null;
        }
        return sub;

    }
    @Override
    public void setEnvironment(Environment environment) {
        kvv2FedSearchBase64SecretRoot = environment.getProperty("vault.kvv2FedSearchBase64SecretRoot");
        kvv2FedSearchBase64SecretPath = environment.getProperty("vault.kvv2FedSearchBase64SecretPath");

    }


    static class FedSearchBase64SecretRequest {
        private String value;

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }


}

