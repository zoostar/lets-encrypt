package net.zoostar.lez;

import java.io.FileWriter;
import java.io.Writer;
import java.security.KeyPair;
import java.security.Security;
import java.util.Collections;
import java.util.Optional;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

public class LetsEncrypt {

	public static void main(String[] args) {
		if (args == null || args.length < 3) {
			printUsage();
			throw new IllegalArgumentException("Expected 3 arguments: <account-email> <sub-domain> <domain-name>");
		}

		Security.addProvider(new BouncyCastleProvider());
		encrypt(args[0], args[1], args[2],
				args.length > 3 && "prod".equalsIgnoreCase(args[3]) ? "acme://letsencrypt.org"
						: "acme://letsencrypt.org/staging");

	}

	private static void printUsage() {
		System.out.println("Usage: java -jar LetsEncrypt.jar <account-email> <sub-domain> <domain-name> [env:prod]");
		System.out.println("Example for Staging: java -jar LetsEncrypt.jar devops@zoostar.net archiva zoostarinc.com");
		System.out.println(
				"Example for Production: java -jar LetsEncrypt.jar devops@zoostar.net portfolio apigator.net prod");
	}

	private static void encrypt(String accountName, String subDomainName, String domainName, String env) {
		// Use staging URL for testing. For production, use "acme://letsencrypt.org"
		String acmeServerUrl = env;
		String domain = subDomainName + "." + domainName;

		try {
			// 1. Generate or load key pairs (Keep your account key pair safe for future
			// renewals!)
			KeyPair accountKeyPair = KeyPairUtils.createKeyPair(4096);
			KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048);

			// 2. Open an ACME session and login/register an account
			Session session = new Session(acmeServerUrl);
			Account account = new AccountBuilder().addEmail(accountName).agreeToTermsOfService()
					.useKeyPair(accountKeyPair).create(session);
			System.out.println("Registered account location: " + account.getLocation());

			// 3. Create a new order for the domain
			Order order = account.newOrder().domains(Collections.singletonList(domain)).create();

			// 4. Authorize ownership via HTTP-01 challenge
			for (Authorization auth : order.getAuthorizations()) {
				if (auth.getStatus() == Status.VALID)
					continue;

				// Find the HTTP-01 challenge
				Optional<Http01Challenge> challenge = auth.findChallenge(Http01Challenge.TYPE);
				if (challenge.isEmpty()) {
					throw new RuntimeException("HTTP-01 challenge not supported by CA");
				}

				// IMPORTANT: Before calling trigger(), you must host the token content
				// at http://<your-domain>/.well-known/acme-challenge/<token>
				System.out.println("--- ACTION REQUIRED ---");
				System.out.println("Host a file at: http://" + domain + "/.well-known/acme-challenge/"
						+ challenge.get().getToken());
				System.out.println("With the exact content: " + challenge.get().getAuthorization());
				System.out.println("-----------------------");

				// Prompt or wait here until you ensure your webserver serves this exact token
				// file
				System.out.println("Press Enter once the token file is live on your server...");
				System.in.read();

				// Tell the CA you are ready for verification
				challenge.get().trigger();

				// Poll until verification succeeds
				while (challenge.get().getStatus() == Status.PENDING
						|| challenge.get().getStatus() == Status.PROCESSING) {
					System.out.println("Checking challenge status...");
					Thread.sleep(3000);
					challenge.get().fetch();
				}

				if (challenge.get().getStatus() != Status.VALID) {
					throw new RuntimeException("Challenge failed. Status: " + challenge.get().getStatus());
				}

				System.out.println("Domain validation successful.");
			}

			// 5. Generate a Certificate Signing Request (CSR)
			CSRBuilder csrBuilder = new CSRBuilder();
			csrBuilder.addDomain(domain);
			csrBuilder.sign(domainKeyPair);
			byte[] csrBytes = csrBuilder.getEncoded();

			// 6. Execute the order with the CSR
			order.execute(csrBytes);

			// Poll until the order completes
			while (order.getStatus() == Status.PENDING || order.getStatus() == Status.PROCESSING) {
				System.out.println("Waiting for certificate issuance...");
				Thread.sleep(3000);
				order.fetch();
			}

			if (order.getStatus() != Status.VALID) {
				throw new RuntimeException("Order execution failed: " + order.getError());
			}

			// 7. Download and save the certificate chain
			Certificate certificate = order.getCertificate();
			try (Writer writer = new FileWriter(subDomainName + ".crt")) {
				certificate.writeCertificate(writer);
			}

			// 8. Save the domain private key
			try (Writer writer = new FileWriter(subDomainName + ".pem")) {
				KeyPairUtils.writeKeyPair(domainKeyPair, writer);
			}

			System.out.println("Certificate saved successfully.");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}