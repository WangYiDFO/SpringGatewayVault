package ca.gc.dfo.edh.fedsearch;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

@SpringBootApplication
@EnableWebFluxSecurity
@EnableCaching
public class FedSearchGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(FedSearchGatewayApplication.class, args);
	}

}
