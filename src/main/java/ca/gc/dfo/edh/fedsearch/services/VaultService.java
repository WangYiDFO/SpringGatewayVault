package ca.gc.dfo.edh.fedsearch.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Service;
import org.springframework.vault.client.RestTemplateBuilder;
import org.springframework.vault.client.SimpleVaultEndpointProvider;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultKeyValueOperations;
import org.springframework.vault.core.VaultKeyValueOperationsSupport;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.authentication.JwtAuthentication;
import org.springframework.vault.authentication.JwtAuthenticationOptions;
import org.springframework.vault.support.VaultResponse;

import java.net.URI;
import java.util.List;
import java.util.Map;

import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.util.context.ContextView;


@Service
public class VaultService implements EnvironmentAware {

    private  VaultTemplate vaultTemplate;
    private String vaultEndPoint;

    private  String vaultJWTLoginPath;

    private  String vaultJWTUserRole;

    public VaultService() {

    }

    public void JWTLogin(String vaultEndPointUrl,String jwtLoginPath,String jwtToken, String role) {
        RestTemplate restTemplate = RestTemplateBuilder.builder()
                .endpointProvider(SimpleVaultEndpointProvider.of(VaultEndpoint.from(URI.create(vaultEndPointUrl))))
                .build();
        // Set up JWT authentication with the provided token
        JwtAuthenticationOptions options = JwtAuthenticationOptions.builder()
                .path(jwtLoginPath)
                .role(role)
//                .jwtSupplier(() -> jwtToken)
                .jwt(jwtToken)
                .build();
        JwtAuthentication jwtAuthentication = new JwtAuthentication(options, restTemplate );
//        VaultToken login = jwtAuthentication.login();

        // Authenticate with Vault using JWT
        vaultTemplate = new VaultTemplate(VaultEndpoint.from(URI.create(vaultEndPointUrl)), jwtAuthentication);
    }

    public void JWTLogin(String jwtToken){
        JWTLogin(vaultEndPoint,vaultJWTLoginPath,jwtToken,vaultJWTUserRole);
    }

    public void writeSecret(String kv_v2_root, String kv_v2_path, List<Map<String, Object>> values) {
        VaultKeyValueOperations vaultKeyValueOperations = vaultTemplate.opsForKeyValue(kv_v2_root, VaultKeyValueOperationsSupport.KeyValueBackend.KV_2) ;
        vaultKeyValueOperations.put(kv_v2_path, values);
    }

    public VaultResponse readSecret(String kv_v2_root, String kv_v2_path) {
        VaultKeyValueOperations vaultKeyValueOperations = vaultTemplate.opsForKeyValue(kv_v2_root, VaultKeyValueOperationsSupport.KeyValueBackend.KV_2) ;
        return vaultKeyValueOperations.get(kv_v2_path);
    }

    public void deleteSecret(String kv_v2_root, String kv_v2_path) {
        VaultKeyValueOperations vaultKeyValueOperations = vaultTemplate.opsForKeyValue(kv_v2_root, VaultKeyValueOperationsSupport.KeyValueBackend.KV_2) ;
        vaultKeyValueOperations.delete(kv_v2_path);
    }

    public boolean updateSecret(String kv_v2_root, String kv_v2_path, Map<String, Object> values) {
        VaultKeyValueOperations vaultKeyValueOperations = vaultTemplate.opsForKeyValue(kv_v2_root, VaultKeyValueOperationsSupport.KeyValueBackend.KV_2) ;
        return vaultKeyValueOperations.patch(kv_v2_path, values);
    }

    public String readBase64Secret(String kv_v2_root, String kv_v2_path) {
        VaultResponse response = readSecret(kv_v2_root, kv_v2_path);
        if (response == null) {
            return null;
        }
        return response.getRequiredData().get("value") == null ? null : response.getRequiredData().get("value").toString();

    }

    public void writeBase64Secret(String kv_v2_root, String kv_v2_path, String value) {
        Map<String, Object> data = Map.of("value", value);
        writeSecret(kv_v2_root, kv_v2_path, List.of(data));
    }

    public void deleteBase64Secret(String kv_v2_root, String kv_v2_path) {
        deleteSecret(kv_v2_root, kv_v2_path);
    }

    public boolean updateBase64Secret(String kv_v2_root, String kv_v2_path, String value) {
        Map<String, Object> data = Map.of("value", value);
        return updateSecret(kv_v2_root, kv_v2_path, data);
    }


    @Override
    public void setEnvironment(Environment environment) {

        vaultEndPoint = environment.getProperty("vault.endpointUrl");
        vaultJWTLoginPath = environment.getProperty("vault.jwtLoginPath");
        vaultJWTUserRole = environment.getProperty("vault.jwtUserRole");

    }
}