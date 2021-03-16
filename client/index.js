const crypto = require("crypto");
const got = require("got");
const readline = require("readline");

const BASE_URL = "http://localhost:8080/api/v1";

async function askUserForCode() {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question("Enter code: ", (code) => {
      rl.close();
      return resolve(code);
    });
  });
}

function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

(async () => {
  const code = await askUserForCode();

  const { challenge } = await got(`${BASE_URL}/challenge`).json();

  const hash = sha256(`${challenge}-${code}`);
  const response = `${challenge}-${hash}`;

  const { token } = await got
    .post(`${BASE_URL}/login`, { json: { response } })
    .json();

  const headers = { "X-My-Auth-Header": token };
  const { secret } = await got(`${BASE_URL}/secret`, { headers }).json();
  console.log("The secret:", secret);
})();
