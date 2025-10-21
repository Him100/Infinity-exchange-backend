package com.infinityexchange.infinityExchange;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class InfinityExchangeApplication {

	public static void main(String[] args) {
		SpringApplication.run(InfinityExchangeApplication.class, args);
	}

}
