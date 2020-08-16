#include "main_wnd.hxx"
#include "ui_main_wnd.h"

// Generate / copy RSA public key buttons.
void MainWindow::on_pb_generate_your_pubkey_clicked() {
    using namespace Ossl;

    if(localKeypair != nullptr) delete localKeypair;

    localKeypair = Rsa::GenerateKeypair(Rsa::KS_4096_B);
    ui->pte_your_pubkey->setPlainText(QString::fromStdString(Rsa::GetPublicKeyPem(localKeypair)));
}

void MainWindow::on_pb_copy_your_pubkey_clicked() {
    QClipboard* clipboard = QGuiApplication::clipboard();
    clipboard->setText(ui->pte_your_pubkey->toPlainText());
}

// Paste RSA public key button.
void MainWindow::on_pb_paste_their_pubkey_clicked() {
    QClipboard* clipboard = QGuiApplication::clipboard();
    const QString& clipboard_text = clipboard->text();

    if(clipboard_text.size() == 774) {
        ui->pte_their_pubkey->setPlainText(clipboard_text);
    } else {
        QMessageBox::warning(this, "Invalid RSA Public Key", "The RSA public key in your clipboard isn't 774 bytes in length, and is therefore invalid.");
    }
}

// Generate / copy AES key from public key buttons.
void MainWindow::on_pb_generate_aes_key_clicked() {
    using namespace Ossl;

    const std::string& public_key_pem = ui->pte_their_pubkey->toPlainText().toStdString();

    if(public_key_pem.size() == 774) {
        RSA* public_key = nullptr;

        try {
            public_key = Rsa::LoadPublicKeyPem(public_key_pem);
        } catch(...) {
            QMessageBox::warning(this, "Failed To Parse Public Key", "The public key that was pasted could not be parsed. Are you sure it's valid?");
            return;
        }

        const std::string& random_hash = Util::Hexlify(Hashing::Sha256Digest(Random::ByteVector(4096)));
        const std::vector<uint8_t> random_hash_bytes(random_hash.begin(), random_hash.end());
        const std::vector<uint8_t> random_hash_encrypted_bytes = Rsa::PublicEncrypt(random_hash_bytes, public_key);

        ui->le_aes_cipherkey->setText(QString::fromStdString(random_hash));
        ui->pte_generated_aes_key->setPlainText(QString::fromStdString(Base64::Encode(random_hash_encrypted_bytes)));        
    } else {
        QMessageBox::warning(this, "Invalid RSA Public Key", "The RSA public key in \"their rsa public key\" isn't 774 byts long. Are you sure it's valid, or filled out?");
    }
}

void MainWindow::on_pb_copy_generated_aes_key_clicked() {
    QClipboard* clipboard = QGuiApplication::clipboard();
    clipboard->setText(ui->pte_generated_aes_key->toPlainText()); 
}

// Paste AES key (decrypts RSA encrypted cipherkey using private key, before pasting).
void MainWindow::on_pb_paste_aes_key_clicked() {
    using namespace Ossl;

    if(localKeypair != nullptr) {
        QClipboard* clipboard = QGuiApplication::clipboard();
        const QString& clipboard_text = clipboard->text();

        if(clipboard_text.size() == 684) {
            const std::vector<uint8_t>& decoded_bytes = Base64::Decode(clipboard_text.toStdString());

            std::vector<uint8_t> decrypted_bytes;

            try {
                decrypted_bytes = Rsa::PrivateDecrypt(decoded_bytes, localKeypair);
            } catch(...) {
                QMessageBox::warning(this, "Unable To Decrypt", "Couldn't decrypt the encrypted AES cipherkey, are you sure it was encrypted with the same public key you sent?");
            }

            if(decrypted_bytes.size() > 0) {
                const std::string aes_cipher_key_string(decrypted_bytes.begin(), decrypted_bytes.end());
                ui->le_aes_cipherkey->setText(QString::fromStdString(aes_cipher_key_string));
            }
        } else {
            QMessageBox::warning(this, "Invalid Key", "The key you copied should be exactly 684 bytes long, it isn't. Are you sure it's valid?");
        }
    } else {
        QMessageBox::warning(this, "No Public Key", "No public key has been generated yet. You have to generate a public key, send the other party your key, have them use it to generate an AES key, which you should then copy and paste here.");
    }
}

// AES Paste your / their message button.
void MainWindow::on_pb_paste_your_message_clicked() {
    QClipboard* clipboard = QGuiApplication::clipboard();
    const QString& clipboard_text = clipboard->text();
    ui->pte_your_plain_message->setPlainText(clipboard_text);
}

void MainWindow::on_pb_paste_their_message_clicked() {
    QClipboard* clipboard = QGuiApplication::clipboard();
    const QString& clipboard_text = clipboard->text();
    ui->pte_their_encrypted_message->setPlainText(clipboard_text);
}

// AES Encrypt/decrypt buttons.
void MainWindow::on_pb_encrypt_your_message_clicked() {
    using namespace Ossl;

    const std::string& aes_cipherkey_string = ui->le_aes_cipherkey->text().toStdString();

    if(aes_cipherkey_string.size() == 64) {
        const std::vector<uint8_t> aes_cipherkey_bytes(aes_cipherkey_string.begin(), aes_cipherkey_string.end());
        
        const std::string& plain_message_string = ui->pte_your_plain_message->toPlainText().toStdString();
        const std::vector<uint8_t> plain_message_bytes(plain_message_string.begin(), plain_message_string.end());

        const std::vector<uint8_t>& encrypted_bytes = Aes::CbcEncryptAuto_Pad_Iv<Aes::KS_256_BIT>(plain_message_bytes, aes_cipherkey_bytes);
        const std::string& encrypted_base64 = Base64::Encode(encrypted_bytes);

        ui->pte_your_encrypted_message->setPlainText(QString::fromStdString(encrypted_base64));
    } else {
        QMessageBox::warning(this, "Invalid AES cipherkey size.", "The AES cipherkey should be 32 bytes in size, it isn't. Are you sure it's valid, or filled out?");
    }
}

void MainWindow::on_pb_decrypt_their_message_clicked() {
    using namespace Ossl;

    const std::string& aes_cipherkey_string = ui->le_aes_cipherkey->text().toStdString();

    if(aes_cipherkey_string.size() == 64) {
        const std::vector<uint8_t> aes_cipherkey_bytes(aes_cipherkey_string.begin(), aes_cipherkey_string.end());
        const std::string& base64_encoded_message = ui->pte_their_encrypted_message->toPlainText().toStdString();

        if(base64_encoded_message.size() >= 24) {
            std::vector<uint8_t> decoded_message_bytes;

            try {
                decoded_message_bytes = Base64::Decode(base64_encoded_message);
            } catch(...) {
                QMessageBox::warning(this, "Base64 Decode Failed", "Failed to base64 decode the input message, can't decrypt. Are you sure it's a valid encrypted message?");
            }

            if(decoded_message_bytes.size() > 0) {
                const std::vector<uint8_t>& decrypted_message_bytes = Aes::CbcDecryptAuto_Pad_Iv<Aes::KS_256_BIT>(decoded_message_bytes, aes_cipherkey_bytes);
                const std::string decrypted_message_string(decrypted_message_bytes.begin(), decrypted_message_bytes.end());

                ui->pte_their_plain_message->setPlainText(QString::fromStdString(decrypted_message_string));
            } 
        } else {
            QMessageBox::warning(this, "Invalid Message Size", "The minimum message size for a base64 encoded message should be 24, it isn't. Are you sure the message is valid, or filled out?");
        }
    } else {
        QMessageBox::warning(this, "Invalid AES cipherkey size.", "The AES cipherkey should be 32 bytes in size, it isn't. Are you sure it's valid, or filled out?");
    }
}

// Copy AES Encryption/Decryption output buttons.
void MainWindow::on_pb_copy_your_encrypted_message_clicked() {
    QClipboard* clipboard = QGuiApplication::clipboard();
    const QString& encrypted_message = ui->pte_your_encrypted_message->toPlainText();
    clipboard->setText(encrypted_message);

}

void MainWindow::on_pb_copy_their_decrypted_message_clicked() {
    QClipboard* clipboard = QGuiApplication::clipboard();
    const QString& decrypted_message = ui->pte_their_plain_message->toPlainText();
    clipboard->setText(decrypted_message);
}

MainWindow::MainWindow(const QString* initial_stylesheet, QWidget* parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    if(initial_stylesheet != nullptr) {
        setStyleSheet(*initial_stylesheet);
    }

    localKeypair = nullptr;
}

MainWindow::~MainWindow() {
    delete ui;
}
