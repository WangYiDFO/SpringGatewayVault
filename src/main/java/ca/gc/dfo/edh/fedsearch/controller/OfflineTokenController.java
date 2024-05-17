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
@RequestMapping("/api/offlinetoken")
public class OfflineTokenController implements EnvironmentAware {

    final Logger logger = LoggerFactory.getLogger(OfflineTokenController.class);

    private final VaultService vaultService;
    private String kvv2OfflineTokenRoot;
    private String kvv2OfflineTokenPath;


    @Autowired
    public OfflineTokenController(VaultService vaultService) {
        this.vaultService = vaultService;
    }

    @PostMapping
    public Mono<String> createOfflineToken(@RequestBody String offlineToken, @RequestHeader("Authorization") String token) {

        String bearerToken = token.substring(7);
        String sub = getSubFromBearerToken(bearerToken);
        if (sub == null) {
            return Mono.error(new Exception("Error parsing JWT or sub"));
        }

        vaultService.JWTLogin(bearerToken);
        vaultService.writeBase64Secret(kvv2OfflineTokenRoot, kvv2OfflineTokenPath.replace("subholder", sub), offlineToken);
        logger.info("User {} create offline token", sub);
        return Mono.just(offlineToken);
    }

    @GetMapping
    public Mono<String> getOfflineTokens(@RequestHeader("Authorization") String token) {
        String bearerToken = token.substring(7);
        String sub = getSubFromBearerToken(bearerToken);
        if (sub == null) {
            return Mono.error(new Exception("Error parsing JWT or sub"));
        }

        vaultService.JWTLogin(bearerToken);
        String offlineToken = vaultService.readBase64Secret(kvv2OfflineTokenRoot, kvv2OfflineTokenPath.replace("subholder", sub));
        if (offlineToken == null) {
            logger.info("User {} does not have offline token", sub);
            return Mono.empty();
        }
        logger.info("User {} get offline token", sub);
        return Mono.just(offlineToken);
    }



    @PutMapping()
    public Mono<String> updateOfflineToken(@RequestHeader("Authorization") String token, @RequestBody String offlineToken) {
        String bearerToken = token.substring(7);
        String sub = getSubFromBearerToken(bearerToken);
        if (sub == null) {
            return Mono.error(new Exception("Error parsing JWT or sub"));
        }

        vaultService.JWTLogin(bearerToken);
        vaultService.updateBase64Secret(kvv2OfflineTokenRoot, kvv2OfflineTokenPath.replace("subholder", sub), offlineToken);
        logger.info("User {} create offline token", sub);
        return Mono.just(offlineToken);
    }

    @DeleteMapping()
    public Mono<Void> deleteOfflineToken(@RequestHeader("Authorization") String token) {
        String bearerToken = token.substring(7);
        String sub = getSubFromBearerToken(bearerToken);
        if (sub == null) {
            return Mono.error(new Exception("Error parsing JWT or sub"));
        }

        vaultService.JWTLogin(bearerToken);
        vaultService.deleteBase64Secret(kvv2OfflineTokenRoot, kvv2OfflineTokenPath.replace("subholder", sub));
        logger.info("User {} delete offline token", sub);
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
        kvv2OfflineTokenRoot = environment.getProperty("vault.kvv2offlineTokenRoot");
        kvv2OfflineTokenPath = environment.getProperty("vault.kvv2offlineTokenPath");

    }
}