all: pwhash

pwhash:
	g++ -Wall -Wextra -O3 -o "pwhash" pwhash.cpp -lcrypto `pkg-config --cflags --libs gtkmm-3.0 libnotify`

clean:
	rm -rf pwhash
