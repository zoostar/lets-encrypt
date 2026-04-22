package net.zoostar.lez;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.Security;
import java.time.Duration;
import java.util.Optional;
import java.util.function.Supplier;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.util.StringUtils;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
@SpringBootApplication
public class LetsEncrypt extends JDialog {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private static final String LABEL_BROWSE = "Browse...";

    // A supplier for a new account KeyPair. The default creates a new EC key pair.
    private static final Supplier<KeyPair> ACCOUNT_KEY_SUPPLIER = KeyPairUtils::createKeyPair;

    // A supplier for a new domain KeyPair. The default creates a RSA key pair.
    private static final Supplier<KeyPair> DOMAIN_KEY_SUPPLIER = () -> KeyPairUtils.createKeyPair(4096);

    // Maximum time to wait until VALID/INVALID is expected
    private static final Duration TIMEOUT = Duration.ofSeconds(60L);

	@Value("${ca.url:https://acme-staging-v02.api.letsencrypt.org/directory}")
	private String caUrl;

	private JTextField domainField;
	
	private JTextField emailField;

	private JTextField userKeyField;
	private File userKeyFile;

	private JTextField domainKeyField;
	private File domainKeyFile;

	private JTextField domainChainField;
	private File domainChainFile;

	private boolean submitted = false;

	public LetsEncrypt() {
		// null parent, title, and true for Modal
		super((Frame) null, "Let's Encrypt", true);
		initUI();
	}

	private void encrypt(String domain) throws IOException, AcmeException, InterruptedException {
		log.info("Begin certificate generation for: {}...", domain);
		Security.addProvider(new BouncyCastleProvider());
		fetchCertificate(domain);
	}

	/**
	 * Generates a certificate for the given domains. Also takes care for the
	 * registration process.
	 *
	 * @param domains Domains to get a common certificate for
	 */
	private void fetchCertificate(String domain) throws IOException, AcmeException, InterruptedException {
		// Load the user key file. If there is no key file, create a new one.
		KeyPair userKeyPair = loadOrCreateUserKeyPair(userKeyFile);

		// Create a session.
		Session session = new Session(caUrl);

		// Get the Account.
		// If there is no account yet, create a new one.
		Account acct = findOrRegisterAccount(session, userKeyPair);

		// Load or create a key pair for the domains. This should not be the userKeyPair!
		KeyPair domainKeyPair = loadOrCreateDomainKeyPair(domainKeyFile);

		// Order the certificate
		Order order = acct.newOrder().domains(domain).create();

		// Perform all required authorizations
		for (Authorization auth : order.getAuthorizations()) {
			authorize(auth);
		}

		// Wait for the order to become READY
		order.waitUntilReady(TIMEOUT);

		// Order the certificate
		order.execute(domainKeyPair);

		// Wait for the order to complete
		Status status = order.waitForCompletion(TIMEOUT);
		if (status != Status.VALID) {
			log.error("Order has failed, reason: {}", order.getError().map(Problem::toString).orElse("unknown"));
			throw new AcmeException("Order failed... Giving up.");
		}

		// Get the certificate
		Certificate certificate = order.getCertificate();

		log.info("Success! The certificate for domain {} has been generated!", domain);
		log.info("Certificate URL: {}", certificate.getLocation());

		// Write a combined file containing the certificate and chain.
		try (FileWriter fw = new FileWriter(domainChainFile)) {
			certificate.writeCertificate(fw);
		}

		// That's all! Configure your web server to use the DOMAIN_KEY_FILE and
		// DOMAIN_CHAIN_FILE for the requested domains.
	}

    /**
     * Loads a user key pair from {@link #USER_KEY_FILE}. If the file does not exist, a
     * new key pair is generated and saved.
     * <p>
     * Keep this key pair in a safe place! In a production environment, you will not be
     * able to access your account again if you should lose the key pair.
     *
     * @return User's {@link KeyPair}.
     */
    private KeyPair loadOrCreateUserKeyPair(File userKeyFile) throws IOException {
        if (userKeyFile.exists()) {
            // If there is a key file, read it
            try (FileReader fr = new FileReader(userKeyFile)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            // If there is none, create a new key pair and save it
            KeyPair userKeyPair = ACCOUNT_KEY_SUPPLIER.get();
            try (FileWriter fw = new FileWriter(userKeyFile)) {
                KeyPairUtils.writeKeyPair(userKeyPair, fw);
            }
            return userKeyPair;
        }
    }

    /**
     * Loads a domain key pair from {@link #DOMAIN_KEY_FILE}. If the file does not exist,
     * a new key pair is generated and saved.
     *
     * @return Domain {@link KeyPair}.
     */
    private KeyPair loadOrCreateDomainKeyPair(File domainKeyFile) throws IOException {
        if (domainKeyFile.exists()) {
            try (FileReader fr = new FileReader(domainKeyFile)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            KeyPair domainKeyPair = DOMAIN_KEY_SUPPLIER.get();
            try (FileWriter fw = new FileWriter(domainKeyFile)) {
                KeyPairUtils.writeKeyPair(domainKeyPair, fw);
            }
            return domainKeyPair;
        }
    }

    /**
     * Authorize a domain. It will be associated with your account, so you will be able to
     * retrieve a signed certificate for the domain later.
     *
     * @param auth
     *         {@link Authorization} to perform
     */
    private void authorize(Authorization auth) throws AcmeException, InterruptedException {
        log.info("Authorization for domain {}", auth.getIdentifier().getDomain());

        // The authorization is already valid. No need to process a challenge.
        if (auth.getStatus() == Status.VALID) {
            return;
        }

        // Find the desired challenge and prepare it.
        Challenge challenge = httpChallenge(auth);

        if (challenge == null) {
            throw new AcmeException("No challenge found");
        }

        // If the challenge is already verified, there's no need to execute it again.
        if (challenge.getStatus() == Status.VALID) {
            return;
        }

        // Now trigger the challenge.
        challenge.trigger();

        // Poll for the challenge to complete.
        Status status = challenge.waitForCompletion(TIMEOUT);
        if (status != Status.VALID) {
            log.error("Challenge has failed, reason: {}", challenge.getError()
                    .map(Problem::toString)
                    .orElse("unknown"));
            throw new AcmeException("Challenge failed... Giving up.");
        }

        log.info("{}", "Challenge has been completed. Remember to remove the validation resource.");
        completeChallenge("Challenge has been completed.\nYou can remove the resource again now.");
    }

    /**
     * Presents the instructions for removing the challenge validation, and waits for
     * dismissal.
     *
     * @param message
     *         Instructions to be shown in the dialog
     */
    public void completeChallenge(String message) {
        JOptionPane.showMessageDialog(null,
                message,
                "Complete Challenge",
                JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Prepares a HTTP challenge.
     * <p>
     * The verification of this challenge expects a file with a certain content to be
     * reachable at a given path under the domain to be tested.
     * <p>
     * This example outputs instructions that need to be executed manually. In a
     * production environment, you would rather generate this file automatically, or maybe
     * use a servlet that returns {@link Http01Challenge#getAuthorization()}.
     *
     * @param auth
     *         {@link Authorization} to find the challenge in
     * @return {@link Challenge} to verify
     */
    public Challenge httpChallenge(Authorization auth) throws AcmeException {
        // Find a single http-01 challenge
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.class)
                .orElseThrow(() -> new AcmeException("Found no " + Http01Challenge.TYPE
                        + " challenge, don't know what to do..."));

        // Output the challenge, wait for acknowledge...
        log.info("Please create a file in your web server's base directory.");
        log.info("It must be reachable at: http://{}/.well-known/acme-challenge/{}",
                auth.getIdentifier().getDomain(), challenge.getToken());
        log.info("File name: {}", challenge.getToken());
        log.info("Content: {}", challenge.getAuthorization());
        log.info("The file must not contain any leading or trailing whitespaces or line breaks!");
        log.info("If you're ready, dismiss the dialog...");

        StringBuilder message = new StringBuilder();
        message.append("Please create a file in your web server's base directory.\n\n");
        message.append("http://")
                .append(auth.getIdentifier().getDomain())
                .append("/.well-known/acme-challenge/");
        acceptChallenge(this, message.toString(), challenge.getToken(), challenge.getAuthorization());

        return challenge;
    }

    /**
     * Presents the instructions for preparing the challenge validation, and waits for
     * dismissal. If the user cancelled the dialog, an exception is thrown.
     *
     * @param message
     *         Instructions to be shown in the dialog
     */
    public void acceptChallenge(JDialog frame, String message, String filename, String content) throws AcmeException {
        InfoDialog dialog = new InfoDialog(frame, message, filename, content);
        dialog.setVisible(true);

        int option = JOptionPane.showConfirmDialog(null,
                message,
                "Prepare Challenge",
                JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.CANCEL_OPTION) {
            throw new AcmeException("User cancelled the challenge");
        }
    }

    /**
     * Finds your {@link Account} at the ACME server. It will be found by your user's
     * public key. If your key is not known to the server yet, a new account will be
     * created.
     * <p>
     * This is a simple way of finding your {@link Account}. A better way is to get the
     * URL of your new account with {@link Account#getLocation()} and store it somewhere.
     * If you need to get access to your account later, reconnect to it via {@link
     * Session#login(URL, KeyPair)} by using the stored location.
     *
     * @param session
     *         {@link Session} to bind with
     * @return {@link Account}
     */
    private Account findOrRegisterAccount(Session session, KeyPair accountKey) throws AcmeException {
        // Ask the user to accept the TOS, if server provides us with a link.
        Optional<URI> tos = session.getMetadata().getTermsOfService();
        if (tos.isPresent()) {
            acceptAgreement(tos.get());
        }

        AccountBuilder accountBuilder = new AccountBuilder()
                .agreeToTermsOfService()
                .useKeyPair(accountKey);

        // Set your email (if available)
        if (StringUtils.hasText(emailField.getText()) ) {
            accountBuilder.addEmail(emailField.getText().trim());
        }

        Account account = accountBuilder.create(session);
        log.info("Registered a new user, URL: {}", account.getLocation());

        return account;
    }

    /**
     * Presents the user a link to the Terms of Service, and asks for confirmation. If the
     * user denies confirmation, an exception is thrown.
     *
     * @param agreement
     *         {@link URI} of the Terms of Service
     */
    public void acceptAgreement(URI agreement) throws AcmeException {
        int option = JOptionPane.showConfirmDialog(null,
                "Do you accept the Terms of Service?\n\n" + agreement,
                "Accept ToS",
                JOptionPane.YES_NO_OPTION);
        if (option == JOptionPane.NO_OPTION) {
            throw new AcmeException("User did not accept Terms of Service");
        }
    }

	private void initUI() {
		setLayout(new BorderLayout(10, 10));

		// --- Input Panel (GridBagLayout for alignment) ---
		JPanel inputPanel = new JPanel(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(10, 10, 5, 10);
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.gridwidth = 1;
		int y = 0;
		int x = 0;

		// Row #1: Domain to generate certificate for
		gbc.gridy = y;
		gbc.gridx = x++;
		inputPanel.add(new JLabel("Domain:"), gbc);

		gbc.gridy = y;
		gbc.gridx = x;
		gbc.gridwidth = 2;
		domainField = new JTextField(50);
		domainField.setToolTipText("Enter a valid sub-domain (e.g. subdomain.example.com)");
		inputPanel.add(domainField, gbc);

		// Row #2: Account email
		x = 0;
		gbc.gridy = ++y;
		gbc.gridx = x++;
		inputPanel.add(new JLabel("Email (Optional):"), gbc);

		gbc.gridy = y;
		gbc.gridx = x;
		gbc.gridwidth = 2;
		emailField = new JTextField(50);
		emailField.setToolTipText("Enter a valid email, if exists.");
		inputPanel.add(emailField, gbc);

		// Row #3: File path where user key will be stored
		x = 0;
		gbc.gridy = ++y;
		gbc.gridx = x++;
		gbc.gridwidth = 1;
		inputPanel.add(new JLabel("User Key File: "), gbc);

		gbc.gridy = y;
		gbc.gridx = x++;
		userKeyField = new JTextField(40);
		userKeyField.setEditable(false);
		userKeyField.setBackground(Color.WHITE);
		userKeyField.setToolTipText("Use the Browse button to select a file.");
		inputPanel.add(userKeyField, gbc);

		gbc.gridy = y;
		gbc.gridx = x;
		JButton userKeyFileBrowseButton = new JButton(LABEL_BROWSE);
		inputPanel.add(userKeyFileBrowseButton, gbc);

		// Row #3
		x = 0;
		gbc.gridy = ++y;
		gbc.gridx = x++;
		gbc.gridwidth = 1;
		inputPanel.add(new JLabel("Domain Key File: "), gbc);

		gbc.gridy = y;
		gbc.gridx = x++;
		domainKeyField = new JTextField(40);
		domainKeyField.setEditable(false);
		domainKeyField.setBackground(Color.WHITE);
		domainKeyField.setToolTipText("Use the Browse button to select a file");
		inputPanel.add(domainKeyField, gbc);

		gbc.gridy = y;
		gbc.gridx = x;
		JButton domainKeyFileBrowseButton = new JButton(LABEL_BROWSE);
		inputPanel.add(domainKeyFileBrowseButton, gbc);

		// Row #4
		x = 0;
		gbc.gridy = ++y;
		gbc.gridx = x++;
		gbc.gridwidth = 1;
		inputPanel.add(new JLabel("Domain Cert File: "), gbc);

		gbc.gridy = y;
		gbc.gridx = x++;
		domainChainField = new JTextField(40);
		domainChainField.setEditable(false);
		domainChainField.setBackground(Color.WHITE);
		domainChainField.setToolTipText("Use the Browse button to select a file");
		inputPanel.add(domainChainField, gbc);

		gbc.gridy = y;
		gbc.gridx = x;
		JButton domainChainFileBrowseButton = new JButton(LABEL_BROWSE);
		inputPanel.add(domainChainFileBrowseButton, gbc);

		// --- Button Panel ---
		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton submitBtn = new JButton("Submit");
		JButton cancelBtn = new JButton("Cancel");
		buttonPanel.add(submitBtn);
		buttonPanel.add(cancelBtn);

		userKeyFileBrowseButton.addActionListener(al -> chooseUserKeyFile());

		domainKeyFileBrowseButton.addActionListener(al -> chooseDomainKeyFile());

		domainChainFileBrowseButton.addActionListener(al -> chooseDomainChainFile());

		submitBtn.addActionListener(ae -> handleSubmit());
		cancelBtn.addActionListener(ae -> System.exit(0)); // Exit app if cancelled on launch

		add(inputPanel, BorderLayout.CENTER);
		add(buttonPanel, BorderLayout.SOUTH);

		pack();
		setLocationRelativeTo(null); // Center on screen
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
	}
	
	// Helper methods extracted to reduce cognitive complexity in initUI()
	
	private void chooseUserKeyFile() {
		JFileChooser chooser = new JFileChooser();
		if (chooser.showOpenDialog(LetsEncrypt.this) == JFileChooser.APPROVE_OPTION) {
			userKeyFile = chooser.getSelectedFile();
			userKeyField.setText(userKeyFile.getAbsolutePath());
		}
	}

	private void chooseDomainKeyFile() {
		JFileChooser chooser = new JFileChooser();
		if (chooser.showOpenDialog(LetsEncrypt.this) == JFileChooser.APPROVE_OPTION) {
			domainKeyFile = chooser.getSelectedFile();
			domainKeyField.setText(domainKeyFile.getAbsolutePath());
		}
	}

	private void chooseDomainChainFile() {
		JFileChooser chooser = new JFileChooser();
		if (chooser.showOpenDialog(LetsEncrypt.this) == JFileChooser.APPROVE_OPTION) {
			domainChainFile = chooser.getSelectedFile();
			domainChainField.setText(domainChainFile.getAbsolutePath());
		}
	}

	private void handleSubmit() {
		if (!StringUtils.hasText(domainField.getText()) || userKeyFile == null) {
			throw new IllegalArgumentException("Domain name is required!");
		}

		submitted = true;
		String domain = domainField.getText().trim();
		try {
			encrypt(domain);
		} catch (InterruptedException e) {
			log.warn(e.getMessage());
			Thread.currentThread().interrupt();
		} catch (IOException | AcmeException e) {
			log.error(e.getMessage(), e);
		} finally {
			dispose(); // Close dialog
		}
	}

	public static void main(String[] args) {
		final ConfigurableApplicationContext context = SpringApplication.run(LetsEncrypt.class, args);

		// Ensure UI runs on the Event Dispatch Thread
		SwingUtilities.invokeLater(() -> {
			LetsEncrypt app = context.getBean(LetsEncrypt.class);
			log.info("Let's encrypt url: {}", app.getCaUrl());
			app.setVisible(true);

			// This code executes AFTER the modal dialog is closed
			if (app.submitted) {
				log.info("Domain: {}", app.domainField.getText());
				log.info("File: {}", app.userKeyFile.getAbsolutePath());
				System.exit(0);
			} else {
				System.exit(0);
			}
		});
	}
}