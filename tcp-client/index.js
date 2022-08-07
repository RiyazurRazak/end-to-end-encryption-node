import net from "net";
import {
  createCipheriv,
  generateKeyPairSync,
  privateDecrypt,
  randomBytes,
} from "crypto";

const PORT = 6000;
const HOST = "127.0.0.1";
const MESSAGE = "hello";

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 1024,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

const client = net.Socket();

client.connect(PORT, HOST, () => {
  console.log("Connection established");
  const payload = {
    key: publicKey,
    algorithm: "RSA",
    mode: "handshake",
  };
  client.write(JSON.stringify(payload));
});

client.on("data", (data) => {
  const recieved_payload = JSON.parse(data);
  if (recieved_payload.mode === "handshake") {
    const symmetric_key = privateDecrypt(
      privateKey,
      Buffer.from(recieved_payload.key, "base64")
    );
    // console.log(symmetric_key.toString("base64"));
    const cipher = createCipheriv(
      "aes256",
      symmetric_key,
      Buffer.from("1234567891234567")
    );
    const encryptedMessage =
      cipher.update(MESSAGE, "utf8", "base64") + cipher.final("base64");

    const payload = {
      message: encryptedMessage,
      algorithm: "AES",
      mode: "message",
    };

    client.write(JSON.stringify(payload));
  }
});

client.on("error", (err) => {
  console.error(err);
});

client.on("close", () => {
  console.log("Connection closed");
});
