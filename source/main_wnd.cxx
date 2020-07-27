#include "main_wnd.hxx"
#include "ui_main_wnd.h"

void MainWindow::on_pb_encrypt_clicked() {
    const std::string& input_string = ui->pte_input->toPlainText().toStdString();

    if(input_string.size()) {
        const std::vector<uint8_t> input_bytes(input_string.begin(), input_string.end());
        const std::string& input_key = ui->le_key->text().toStdString();

        const std::vector<uint8_t>& output_bytes = Crypto::Aes256CbcAutoEncrypt(input_bytes, input_key);
        const std::string& base64_output = Crypto::Base64::Encode(output_bytes);

        ui->pte_output->setPlainText(QString::fromStdString(base64_output));
    }
}

void MainWindow::on_pb_decrypt_clicked() {
    const std::string& base64_input = ui->pte_input->toPlainText().toStdString();

    if(base64_input.size() > 4) {
        const std::string& input_key = ui->le_key->text().toStdString();

        const std::vector<uint8_t>& input_bytes = Crypto::Base64::Decode(base64_input);

        const std::vector<uint8_t>& output_bytes = Crypto::Aes256CbcAutoDecrypt(input_bytes, input_key);
        const std::string output_string(output_bytes.begin(), output_bytes.end());

        ui->pte_output->setPlainText(QString::fromStdString(output_string));
    }
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    std::ifstream ifile_stream("./theme.qss", std::ios::binary);

    if(ifile_stream.good()) {
        const std::string style_sheet((std::istreambuf_iterator<char>(ifile_stream)), (std::istreambuf_iterator<char>()));
        ifile_stream.close();

        setStyleSheet(QString::fromStdString(style_sheet));
    }

    ui->setupUi(this);
}

MainWindow::~MainWindow() {
    delete ui;
}
