package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	wskeyauth "github.com/clubcabana/ws-key-auth/golang"
)

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()

		authenticated, clientID, err := wskeyauth.Handshake(conn)

		if !authenticated || err != nil {
			log.Println(err)
			log.Println("Failed to authenticate")
			return
		}

		log.Println("Authenticated")

		conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Client ID: %s", clientID)))

		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Println("read:", err)
				break
			}
			log.Printf("recv: %s", message)

			err = conn.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				log.Println("write:", err)
				break
			}
		}
	})
	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
