#include <QApplication>
#include <QString>

#include <fstream>
#include <string>

#include "main_wnd.hxx"
#include "dependencies/crypto-utils.hxx"

int main(int argc, char* argv[]) {
    /* Stylesheet Load priority
     * 1.) Stylesheet file, as command line argument --style-file
     * 2.) Stylesheet b64 string, as command line argument --style-b64
     * 3.) Resorts to looking for style.qss in working directory.
     * 4.) Uses HARDCODED_STYLE macro, if it's defined.
     * 5.) Default to the OS's native style.
     */

    QString qss_stylesheet;

    for(int i=0; i < argc; ++i) {
        const char* next_argument = (i+1) < argc ? argv[i+1] : nullptr;
        const char* argument = argv[i];

        if(next_argument != nullptr) {
            if(!_stricmp(argument, "--style-file")) {
                std::ifstream ifile_stream(next_argument, std::ios::binary);

                if(ifile_stream.good()) {
                    std::string stylesheet_string((std::istreambuf_iterator<char>(ifile_stream)), (std::istreambuf_iterator<char>()));
                    qss_stylesheet = QString::fromStdString(stylesheet_string);
                } else {
                    std::cerr << "Could not open a valid stream to the stylesheet file." << std::endl;
                    return 1;
                }

            } else if(!_stricmp(argument, "--style-b64")) {
                using namespace Ossl;

                const std::string encoded_string(next_argument);
                
                try {
                    const std::vector<uint8_t>& decoded_bytes = Base64::Decode(encoded_string);
                    const std::string decoded_string(decoded_bytes.begin(), decoded_bytes.end());

                    qss_stylesheet = QString::fromStdString(decoded_string);
                } catch(...) {
                    std::cerr << "Could not decode the provided base64 stylesheet." << std::endl;
                    return 2;
                }
            }
        }
    }

    if(qss_stylesheet.size() == 0) {
        std::ifstream ifile_stream("./style.qss", std::ios::binary);

        if(ifile_stream.good()) {
            std::string stylesheet_string((std::istreambuf_iterator<char>(ifile_stream)), (std::istreambuf_iterator<char>()));
            qss_stylesheet = QString::fromStdString(stylesheet_string);
        } else {
            #ifdef HARDCODED_STYLESHEET
            qss_stylesheet = QString::fromStdString(HARDCODED_STYLESHEET)
            #endif
        }
    }

    QApplication application(argc, argv);
    MainWindow main_window(qss_stylesheet.size() > 0 ? &qss_stylesheet : nullptr);
    main_window.show();

    return application.exec();
}
