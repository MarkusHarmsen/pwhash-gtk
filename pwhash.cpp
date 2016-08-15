#include <gtkmm.h>
#include <iostream>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <libnotify/notify.h>

#define HASH_LENGTH             40
#define HASH_MAX_RESULT_LENGTH  26

Gtk::Window     *pWindow    = 0;
Gtk::Entry      *pTag       = 0;
Gtk::Entry      *pPassword  = 0;
Gtk::SpinButton *pLength    = 0;

/*
 * Show notification
 */
static void notify() {
  notify_init("Password created");
  NotifyNotification *notify = notify_notification_new("Password created", "The Password has been copied to clipboard", "dialog-password-symbolic");
  notify_notification_show (notify, NULL);
}

/*
 * Convert string to base64
 */
static char *base64(const unsigned char *input, int buffer_length) {
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, buffer_length);
  (void)BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buff = (char *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;

  BIO_free_all(b64);

  return buff;
}

/*
 * Build HMAC SHA1(key, data) and encode the result base64.
 * Return a substring(0, length), with 0 < length <= 26.
 *
 * Compatible with hashapass (http://hashapass.com/en/index.html) when using a length of 8.
 *
 * Why only 26 chars?
 *   When encode base64, we can store more information in a string as we could in a base16 one (SHA1 hash).
 *   Therefore the base64 encoded string uses padding ('A's) to extend the length.
 */
static char *generate_hash(const char *data, const char *key, unsigned int length) {
    // HMAC SHA1(key, data)
    unsigned char *digest = HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, strlen(data), NULL, NULL);

    // Base64 encode
    char *code = base64(digest, HASH_LENGTH);

    // Limit length (0 < length <= 26)
    length = length < 1           ? 1 : length;
    length = length > HASH_MAX_RESULT_LENGTH ? HASH_MAX_RESULT_LENGTH : length;

    // Set length
    code[length] = '\0';

    return code;
}

static void on_password_activated() {
  if(pWindow && pTag && pLength && pPassword) {

    char *code = generate_hash(
      pTag->get_text().c_str(),       // data
      pPassword->get_text().c_str(),  // key
      pLength->get_value_as_int()     // length
    );

    // Copy to clipboard
    Glib::RefPtr<Gtk::Clipboard> refClipboard = Gtk::Clipboard::get();
    refClipboard->set_text(code);

    // Notify
    notify();

    free(code);

    pWindow->hide(); //hide() will cause main::run() to end.
  }
}

int main (int argc, char **argv) {
  Glib::RefPtr<Gtk::Application> app = Gtk::Application::create(argc, argv, "de.markus.pwhash");

  //Load the GtkBuilder file and instantiate its widgets:
  Glib::RefPtr<Gtk::Builder> refBuilder = Gtk::Builder::create();
  try {
    refBuilder->add_from_file("pwhash.glade");
  } catch(const Glib::FileError& ex) {
    std::cerr << "FileError: " << ex.what() << std::endl;
    return 1;
  } catch(const Glib::MarkupError& ex) {
    std::cerr << "MarkupError: " << ex.what() << std::endl;
    return 1;
  } catch(const Gtk::BuilderError& ex) {
    std::cerr << "BuilderError: " << ex.what() << std::endl;
    return 1;
  }

  //Get the GtkBuilder-instantiated Dialog:
  refBuilder->get_widget("window", pWindow);
  if(pWindow) {
    refBuilder->get_widget("entry_tag", pTag);
    refBuilder->get_widget("spin_length", pLength);

    refBuilder->get_widget("entry_password", pPassword);
    if(pPassword) {
      pPassword->signal_activate().connect(sigc::ptr_fun(on_password_activated));
    }

    app->run(*pWindow);
  }

  delete pWindow;
  delete pTag;
  delete pPassword;

  return 0;
}
