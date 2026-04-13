package net.zoostar.lez;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class InfoDialog extends JDialog {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public InfoDialog(JDialog parent, String title, String filename, String content) {
        super(parent, title, true); // 'true' makes it modal
        
        // 1. Layout Configuration
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // 2. The Non-Editable Field
        JTextField textFilenameField = new JTextField(filename, 50);
        textFilenameField.setEditable(false);
        textFilenameField.setBackground(Color.WHITE); // Keep it looking clean
        
        // 3. The Copy Button
        JButton copyFilenameButton = new JButton("Copy");
        copyFilenameButton.addActionListener(ae -> {
        	log.trace("Copy Filename Button Action Event: {}", ae);
            StringSelection selection = new StringSelection(textFilenameField.getText());
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            JOptionPane.showMessageDialog(this, "Copied Filename to clipboard!");
        });

        // 4. The Non-Editable Field
        JTextField textContentField = new JTextField(content, 100);
        textContentField.setEditable(false);
        textContentField.setBackground(Color.WHITE); // Keep it looking clean
        
        // 5. The Copy Button
        JButton copyContentButton = new JButton("Copy");
        copyContentButton.addActionListener(ae -> {
        	log.trace("Copy Content Button Action Event: {}", ae);
            StringSelection selection = new StringSelection(textContentField.getText());
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            JOptionPane.showMessageDialog(this, "Copied Filename to clipboard!");
        });

        int y = 0;
        int x = 0;
        
        // 6. Adding Components
        gbc.gridy = y++;
        gbc.gridx = x++;
        add(new JLabel("Filename:"), gbc);

        gbc.gridx = x++;
        add(textFilenameField, gbc);

        gbc.gridx = x;
        add(copyFilenameButton, gbc);

        x = 0;
        gbc.gridy = y;
        gbc.gridx = x++;
        add(new JLabel("Content:"), gbc);

        gbc.gridx = x++;
        add(textContentField, gbc);

        gbc.gridx = x;
        add(copyContentButton, gbc);

        // 7. Dialog Settings
        pack();
        setLocationRelativeTo(parent);
    }
}