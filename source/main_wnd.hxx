#ifndef MAIN_WND_HXX
#define MAIN_WND_HXX

#include <QMainWindow>

#include <fstream>
#include <vector>

#include "dependencies/crypto.hxx"

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow {
private: Q_OBJECT
    Ui::MainWindow* ui;

protected slots:
    void on_pb_encrypt_clicked();
    void on_pb_decrypt_clicked();

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();
};

#endif // MAIN_WND_HXX
