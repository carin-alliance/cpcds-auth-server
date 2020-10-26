package org.hl7.cpcdsauthserver;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCrypt;

@SpringBootApplication
public class App {

	private static Database DB;
	private static RSAPublicKey publicKey;
	private static RSAPrivateKey privateKey;
	private static final Logger logger = ServerLogger.getLogger();
	private static final String ehrServer = "http://ec2-18-217-72-168.us-east-2.compute.amazonaws.com:8080/cpcds-server/fhir";
	private static final String keyId = "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg";

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		logger.info("App::Initializing server");

		initializeDB();

		initializeRSAKeys();

		SpringApplication.run(App.class, args);
	}

	private static void initializeDB() {
		if (DB == null)
			DB = new Database();

		// Add default Clients and Users
		Client heroku = new Client("6cfecf41-e364-44ab-a06f-77f8b0c56c2b", "XHNdbHQlOrWXQ8eeXHvZal1EDjI3n2ISlqhtP30Zc89Ad2NuzreoorWQ5P8dPrxtk267SJ23mbxlMzjriAGgkaTnm6Y9f1cOas4Z6xhWXxG43bkIKHhawMR6gGDXAuEWc8wXUHteZIi4YCX6E1qAvGdsXS1KBhkUf1CLcGmauhbCMd73CjMugT527mpLnIebuTp4LYDiJag0usCE6B6fYuTWV21AbvydLnLsMsk83T7aobE4p9R0upL2Ph3OFTE1", "https://cpcds-client-ri.herokuapp.com/login");
		Client localhost = new Client("b0c46635-c0b4-448c-a8b9-9bd282d2e05a", "bUYbEj5wpazS8Xv1jyruFKpuXa24OGn9MHuZ3ygKexaI5mhKUIzVEBvbv2uggVf1cW6kYD3cgTbCIGK3kjiMcmJq3OG9bn85Fh2x7JKYgy7Jwagdzs0qufgkhPGDvEoVpImpA4clIhfwn58qoTrfHx86ooWLWJeQh4s0StEMqoxLqboywr8u11qmMHd1xwBLehGXUbqpEBlkelBHDWaiCjkhwZeRe4nVu4o8wSAbPQIECQcTjqYBUrBjHlMx5vXU", "http://localhost:4000/login");
		User user1 = new User("user1", BCrypt.hashpw("password1", BCrypt.gensalt()), "1");
		User user689 = new User("user689", BCrypt.hashpw("password689", BCrypt.gensalt()), "689");
		User patient1 = new User("patient1", BCrypt.hashpw("password1", BCrypt.gensalt()), "Patient1");
		User patientex1 = new User("patientex1", BCrypt.hashpw("passwordex1", BCrypt.gensalt()), "PatientEx1");
		User admin = new User("admin", BCrypt.hashpw("123456789", BCrypt.gensalt()), "admin");

		DB.write(heroku);
		DB.write(localhost);
		DB.write(user1);
		DB.write(user689);
		DB.write(patient1);
		DB.write(patientex1);
		DB.write(admin);
	}

	private static void initializeRSAKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
		/*
		 * Code to generate keys adpated from
		 * https://stackoverflow.com/questions/24546397/generating-rsa-keys-for-given-
		 * modulus-and-exponent
		 * 
		 * p :
		 * 72685705065169728266450789649852557970253453395982124202036441196258256631809
		 * q :
		 * 78284536054273880334636739102056358277733743810954757271523407605758722854617
		 * Public Key :
		 * 30819a300d06092a864886f70d01010105000381880030818402406ca4f49908368ecdb45458942ab9360fc4e52a3540b955fe8e2f764c51a5f09a8bc32c8222f7e3abc30bc405327de78c6b988bc4cc81de367737163b92bdc6d90240308b84d7670d1aa24477bf2df8bb81f0268c4557240367befd67452777f798d1b029d2add2fbbcbd9a6f95dd8732903b6884636cedba6226bb9da631c20069f9
		 * Private Key :
		 * 3081b1020100300d06092a864886f70d010101050004819c30819902010002406ca4f49908368ecdb45458942ab9360fc4e52a3540b955fe8e2f764c51a5f09a8bc32c8222f7e3abc30bc405327de78c6b988bc4cc81de367737163b92bdc6d9020100024059287f5af88d7173c627008266f4b8da84f9290971502e1f52d709102fb2b11cd49e248756fd51867119e18db7c40f9f4d360b3ac4eeab5db070a5014aee4849020100020100020100020100020100
		 */
		BigInteger modulus = new BigInteger(
				"5690166698804597197330905768480486858877596610886363234480576904931540875874759967271069328480055496837733730620168171327423013607454238318286896004712153");
		BigInteger publicExponent = new BigInteger(
				"2542507730329925502019959402417157606871382892503593304032212496853538284138894186312740754437083011799807189636117018396940516735918014461610794552420857");
		BigInteger privateExponent = new BigInteger(
				"4669593480441015206282423283120213741469693238159411936473600414351862440739333747236900477132741820141503738805857072650451472878490200305741807022393417");

		KeyFactory kf = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
		RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
		publicKey = (RSAPublicKey) kf.generatePublic(publicKeySpec);
		privateKey = (RSAPrivateKey) kf.generatePrivate(privateKeySpec);
	}

	public static Database getDB() {
		return DB;
	}

	public static String getKeyId() {
		return App.keyId;
	}

	public static RSAPublicKey getPublicKey() {
		return App.publicKey;
	}

	public static RSAPrivateKey getPrivateKey() {
		return App.privateKey;
	}

	public static String getEhrServer(HttpServletRequest request) {
		return App.ehrServer;
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
