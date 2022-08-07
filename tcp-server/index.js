import net from "net";
import { randomBytes, publicEncrypt, createDecipheriv } from "crypto";

const PORT = 6000;
const HOST = "127.0.0.1";

let symmetric_key = null;

const server = net.createServer((socket) => {
  socket.on("data", (data) => {
    const recieved_payload = JSON.parse(data);
    if (recieved_payload.mode === "handshake") {
      //generate 32 bit symmetric key
      symmetric_key = randomBytes(32);
      // verify the key by log to check both the client and server has the same key
      //   console.log(symmetric_key.toString("base64"));

      // encrypt using the public key
      const encrypted_key = publicEncrypt(recieved_payload.key, symmetric_key);

      const payload = {
        key: encrypted_key.toString("base64"),
        algorithm: "AES",
        mode: "handshake",
      };
      socket.write(JSON.stringify(payload));
    } else if (recieved_payload.mode === "message") {
      const cipher = createDecipheriv(
        "aes256",
        symmetric_key,
        Buffer.from("1234567891234567")
      );
      const message =
        cipher.update(recieved_payload.message, "base64", "utf-8") +
        cipher.final("utf-8");
      console.log(`Encoded recieved message: ${recieved_payload.message}`);
      console.log(`Decoded recieved message: ${message}`);
    } else {
      console.log("Unidentified MODE 404");
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log("Server started to listen");
});
