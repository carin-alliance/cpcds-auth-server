package org.hl7.cpcdsauthserver;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class App {

	private static String secret;

	public static void main(String[] args) {
		// Set the secret
		if (System.getenv("jwt.secret") != null)
			App.secret = System.getenv("jwt.secret");
		else
			App.secret = "secret";

		SpringApplication.run(App.class, args);
	}

	public static String getSecret() {
		return App.secret;
	}

	/**
	 * Get the base url of the service from the HttpServletRequest
	 * 
	 * @param request - the HttpServletRequest from the controller
	 * @return the base url for the service
	 */
	public static String getServiceBaseUrl(HttpServletRequest request) {
		return request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort()
				+ request.getContextPath();
	}

}
