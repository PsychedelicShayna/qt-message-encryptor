#ifndef MAIN_WND_HXX
#define MAIN_WND_HXX

#include <QMainWindow>
#include <QMessageBox>
#include <QClipboard>

#include <sstream>
#include <fstream>
#include <vector>

#include "dependencies/abstract-ossl.hxx"

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow {
private: Q_OBJECT
    Ui::MainWindow* ui;

    RSA* localKeypair;

protected slots:
    // Generate / copy RSA public key buttons.
    void on_pb_generate_your_pubkey_clicked();
    void on_pb_copy_your_pubkey_clicked();

    // Paste RSA public key button.
    void on_pb_paste_their_pubkey_clicked();

    // Generate / copy AES key from public key buttons.
    void on_pb_generate_aes_key_clicked();
    void on_pb_copy_generated_aes_key_clicked();

    // Paste AES key (decrypts RSA encrypted cipherkey using private key, before pasting).
    void on_pb_paste_aes_key_clicked();

    // AES Paste your / their message button.
    void on_pb_paste_your_message_clicked();
    void on_pb_paste_their_message_clicked();

    // AES Encrypt/decrypt buttons.
    void on_pb_encrypt_your_message_clicked();
    void on_pb_decrypt_their_message_clicked();

    // Copy AES Encryption/Decryption output buttons.
    void on_pb_copy_your_encrypted_message_clicked();
    void on_pb_copy_their_decrypted_message_clicked();

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();
};

#endif // MAIN_WND_HXX


