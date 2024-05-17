package ca.gc.dfo.edh.fedsearch.filters.factories;

import ca.gc.dfo.edh.fedsearch.services.VaultService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import com.nimbusds.jwt.*;


import java.text.ParseException;
import java.util.*;

import static org.springframework.cloud.gateway.support.GatewayToStringStyler.filterToStringCreator;

@Component
public class Base64HeaderGatewayFilterFactory extends AbstractGatewayFilterFactory<Base64HeaderGatewayFilterFactory.Config> implements EnvironmentAware {

    private VaultService vaultService;

    private final CacheManager cacheManager;
    private String vaultEndPoint;

    private  String vaultJWTLoginPath;

    private  String vaultJWTUserRole;
    final Logger logger = LoggerFactory.getLogger(Base64HeaderGatewayFilterFactory.class);

    public Base64HeaderGatewayFilterFactory(CacheManager cacheManager, VaultService vaultService) {
        super(Config.class);
        this.cacheManager = cacheManager;
        this.vaultService = vaultService;
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("base64-header");
    }

    @Override
    public GatewayFilter apply(Config config) {
        return new GatewayFilter() {
            @Override
            public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

                String kv_v2_secretRoot = ServerWebExchangeUtils.expand(exchange, config.getKvv2SecretRoot());
                String kv_v2_secretPath = ServerWebExchangeUtils.expand(exchange, config.getKvv2SecretPath());

                final String authorizationHeaderValue = exchange.getRequest().getHeaders().getFirst("Authorization");
                if (authorizationHeaderValue == null || !authorizationHeaderValue.startsWith("Bearer")) {
                    logger.info("user does not have authorization header, or it is not Bearer. do nothing");
                    return chain.filter(exchange);
                }

                String token = authorizationHeaderValue.substring(7);

                JWT jwt;
                String sub;
                try{
                    jwt = JWTParser.parse(token);
                    sub = jwt.getJWTClaimsSet().getSubject();
                }catch ( ParseException e){
                    logger.warn("Error parsing JWT or sub", e);
                    return chain.filter(exchange);
                }

                logger.info("user {} access {}", sub, exchange.getRequest().getPath());

                final Cache cache = cacheManager.getCache("base64Header");
                String base64Header = cache != null ? cache.get(kv_v2_secretPath.replace("subholder", sub), String.class) : null;

                if (base64Header != null) {
                    logger.info("user {} has base64 header in cache", sub);
                    String finalBase64Header1 = base64Header;
                    ServerHttpRequest request = exchange.getRequest().mutate().headers(httpHeaders -> {
                        httpHeaders.remove("Authorization");
                        httpHeaders.add("Authorization", "Basic " + finalBase64Header1);
                    }).build();
                    return chain.filter(exchange.mutate().request(request).build());
                }

                try{
                    logger.info("user {} try get base64 header from vault", sub);
                    vaultService.JWTLogin(vaultEndPoint, vaultJWTLoginPath, token, vaultJWTUserRole);
                    base64Header = vaultService.readBase64Secret(kv_v2_secretRoot, kv_v2_secretPath.replace("subholder", sub));

                }catch (Exception e){
                    logger.warn("Error reading base64 secret", e);
                    return chain.filter(exchange);
                }

                if (base64Header == null) {
                    // do nothing, keep going to next filter
                    logger.info("user {} does not have base64 header in vault", sub);
                    return chain.filter(exchange);
                }

                if (cache != null) {
                    logger.info("user {} put base64 header {} in cache", sub, kv_v2_secretPath.replace("subholder", sub));
                    cache.putIfAbsent(kv_v2_secretPath.replace("subholder", sub), base64Header);
                }
                String finalBase64Header = base64Header;
                ServerHttpRequest request = exchange.getRequest().mutate().headers(httpHeaders -> {
                    httpHeaders.remove("Authorization");
                    httpHeaders.add("Authorization", "Basic " + finalBase64Header);
                }).build();


                return chain.filter(exchange.mutate().request(request).build());
           }

            @Override
            public String toString() {
                return filterToStringCreator(Base64HeaderGatewayFilterFactory.this).append(config.getKvv2SecretPath())
                        .toString();
            }
        };
    }

    @Override
    public void setEnvironment(Environment environment) {
        vaultEndPoint = environment.getProperty("vault.endpointUrl");
        vaultJWTLoginPath = environment.getProperty("vault.jwtLoginPath");
        vaultJWTUserRole = environment.getProperty("vault.jwtUserRole");
    }

    public static class Config {

        private String kvv2SecretRoot;
        private String kvv2SecretPath;
        public String getKvv2SecretRoot() {
            return kvv2SecretRoot;
        }

        public void setKvv2SecretRoot(String kvv2SecretRoot) {
            this.kvv2SecretRoot = kvv2SecretRoot;
        }

        public String getKvv2SecretPath() {
            return kvv2SecretPath;
        }

        public void setKvv2SecretPath(String kvv2SecretPath) {
            this.kvv2SecretPath = kvv2SecretPath;
        }



    }

}