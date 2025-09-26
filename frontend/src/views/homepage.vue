<script setup>
import { ref, onMounted, computed } from "vue";
import { Buffer } from "buffer";
import VueJsonPretty from "vue-json-pretty";
import "vue-json-pretty/lib/styles.css";

globalThis.Buffer = Buffer;

const API_BASE = "http://127.0.0.1:8000"; // FastAPI backend

// --- Reactive state ---
const clientECDHE = ref({});
const clientPQC = ref({});
const serverECDHE = ref({});
const serverPQC = ref({});

const sharedECDHE = ref("");
const sharedPQC = ref("");
const combinedSecret = ref("");
const sessionKey = ref("");

const message = ref("Hello server!");
const ciphertext = ref("");
const decryptedMessage = ref("");

const error = ref(false);

// --- API functions ---
async function generateKeys() {
  try {
    const res = await fetch(`${API_BASE}/keys`);
    const data = await res.json();

    // client
    clientECDHE.value = { ecdhe_pk: data.client.ecdhe_pk };
    clientPQC.value = { pqc_pk: data.client.pqc_pk };

    // server
    serverECDHE.value = { ecdhe_pk: data.server.ecdhe_pk };
    serverPQC.value = { pqc_pk: data.server.pqc_pk };

    console.log("✅ Keys generated");
  } catch (err) {
    console.error("❌ Error generating keys", err);
  }
}

async function computeSharedSecrets() {
  try {
    const res = await fetch(`${API_BASE}/shared-secrets`);
    const data = await res.json();
    sharedECDHE.value = data.ecdhe_shared;
    sharedPQC.value = data.pqc_shared;
    combinedSecret.value = data.combined_secret;
    console.log("✅ Shared secrets computed");


  } catch (err) {
    console.error("❌ Error computing shared secrets", err);
  }
}

async function deriveSessionKey() {
  try {
    if (!sharedECDHE.value || !sharedPQC.value) {
      console.error("❌ Cannot derive session key without shared secrets");
      return;
    }

    const res = await fetch(`${API_BASE}/session-key`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ecdhe_secret: sharedECDHE.value,
        pqc_secret: sharedPQC.value,
      }),
    });

    const data = await res.json();
    sessionKey.value = data.session_key; // base64 string
    console.log("✅ Derived session key:", sessionKey.value);
  } catch (err) {
    console.error("❌ Error deriving session key", err);
  }
}

async function encryptMessage() {
  try {
    if (!sessionKey.value) {
      console.error("❌ No session key derived yet!");
      return;
    }

    const res = await fetch(`${API_BASE}/encrypt`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: message.value,
        session_key: sessionKey.value,
      }),
    });

    const data = await res.json();
    ciphertext.value = data;
    console.log("✅ Message encrypted:", ciphertext.value);
  } catch (err) {
    console.error("❌ Error encrypting message", err);
  }
}

async function decryptMessage() {
  try {
    if (!ciphertext.value.ciphertext) {
      console.error("❌ No ciphertext to decrypt");
      return;
    }

    const res = await fetch(`${API_BASE}/decrypt`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_key: sessionKey.value,
        nonce: ciphertext.value.nonce,
        ciphertext: ciphertext.value.ciphertext,
      }),
    });

    if (!res.ok) throw new Error("Decryption failed");

    const data = await res.json();
    decryptedMessage.value = data.message;
    error.value = false;
    console.log("✅ Message decrypted:", decryptedMessage.value);
  } catch (err) {
    console.error("❌ Error decrypting message", err);
    error.value = true;
  }
}

function byteLength(base64OrString) {
  if (!base64OrString) return 0;
  try {
    return Buffer.from(base64OrString, "base64").length; // decode if base64
  } catch {
    return Buffer.from(base64OrString).length; // fallback raw
  }
}

onMounted(() => {
  console.log("⚡ Frontend ready");
});
</script>

<template>
  <TabView>
    <!-- Setup Tab -->
    <TabPanel header="Setup">
      <div id="container">
        <Card>
          <template #title>
            <h3>Key Generation</h3>
          </template>
          <template #content>
            <Button label="Generate Keys" @click="generateKeys" />
            <Panel header="Client's Keys" toggleable>
              <vue-json-pretty :data="clientECDHE"/>
              <small v-if="clientECDHE.ecdhe_pk">({{ byteLength(clientECDHE.ecdhe_pk) }} bytes)</small>
              <br>
              <br>
              <vue-json-pretty :data="clientPQC"/>
              <small v-if="clientPQC.pqc_pk">({{ byteLength(clientPQC.pqc_pk) }} bytes)</small>
            </Panel>
            <Panel header="Server's Keys" toggleable>
              <vue-json-pretty :data="serverECDHE"/>
              <small v-if="serverECDHE.ecdhe_pk">({{ byteLength(serverECDHE.ecdhe_pk) }} bytes)</small>
              <br>
              <br>
              <vue-json-pretty :data="serverPQC"/>
              <small v-if="serverPQC.pqc_pk">({{ byteLength(serverPQC.pqc_pk) }} bytes)</small>
            </Panel>
          </template>
        </Card>
      </div>
    </TabPanel>

    <!-- Shared Secrets Tab -->
    <TabPanel header="Shared Secrets">
      <div id="container2">
      <Card>
        <template #title>
          <h3>Shared Secrets</h3>
        </template>
        <template #content>
          <Button label="Compute Shared Secrets" @click="computeSharedSecrets"  class="full-row"/>
          <div class="secrets-grid">
            <!-- Left column -->
            <Panel header="ECDHE Shared Secret" toggleable>
              <vue-json-pretty :data="sharedECDHE" />
              <small v-if="sharedECDHE">({{ byteLength(sharedECDHE) }} bytes)</small>
            </Panel>

            <!-- Right column -->
            <Panel header="PQC Shared Secret" toggleable>
              <vue-json-pretty :data="sharedPQC" />
              <small v-if="sharedPQC">({{ byteLength(sharedPQC) }} bytes)</small>
            </Panel>

            <!-- Full width row -->
            <Panel header="Combined Secret (concatenation of the ECDHE and PQC shared secrets)" toggleable class="full-row">
              <vue-json-pretty :data="combinedSecret" />
              <small v-if="combinedSecret">({{ byteLength(combinedSecret) }} bytes)</small>
            </Panel>
          </div>
        </template>
      </Card>

        <Card>
          <template #title>
            <h3>Session Key</h3>
          </template>
          <template #content>
             <Button label="Derive Session Key" @click="deriveSessionKey"  class="full-row"/> 
          <p style="margin:10px 0; font-style:italic; color:#444;">
              The session key is derived from the <b>ECDHE</b> and <b>PQC</b> shared secrets <b>(combined secret)</b>.
            </p>
             <div class="secrets-grid">
            <Panel header="Session Key" toggleable class="full-row">
              <vue-json-pretty :data="sessionKey"/>
              <small v-if="sessionKey">({{ byteLength(sessionKey) }} bytes)</small>
            </Panel>
            </div>
          </template>
        </Card>
      </div>
    </TabPanel>

<!-- Encrypt Tab -->
    <TabPanel header="Encrypt">
      <div class="encrypt-tab-container" id="container3">
        <div class="encrypt-boxes">
          <!-- Left column: Message + Session Key -->
          <div class="left-column">
            <Card>
              <template #title>
                <h3>Message to Encrypt</h3>
              </template>
              <template #content>
                <Textarea 
                  v-model="message" 
                  placeholder="Type your message..." 
                  style="width: 100%" 
                  rows="5"
                />
              </template>
            </Card>
            <div style="font-size: 24px; font-weight: bold; color: white;">+</div>

            <Card>
              <template #title>
                <h3>Session Key</h3>
              </template>
              <template #content>
                <vue-json-pretty :data="sessionKey"/>
                <small v-if="sessionKey">({{ byteLength(sessionKey) }} bytes)</small>
              </template>
            </Card>
          </div>

          <!-- Right column: Ciphertext -->
          <div class="right-column">
            <Card>
              <template #title>
                <h3>Encrypted Message</h3>
              </template>
              <template #content>
                <vue-json-pretty :data="ciphertext" />
                <small v-if="ciphertext.ciphertext">
                  ({{ byteLength(ciphertext.ciphertext) }} bytes ciphertext)
                </small>
                <br />
                <small v-if="ciphertext.nonce">
                  ({{ byteLength(ciphertext.nonce) }} bytes nonce)
                </small>
                </template>
            </Card>
          </div>
        </div>

        <Button 
          label="Encrypt" 
          @click="encryptMessage" 
          style="margin-top: 20px; width: 50%"
        />
      </div>
    </TabPanel>

<!-- Decrypt Tab -->
    <TabPanel header="Decrypt">
      <div class="encrypt-tab-container" id="container4">
      <div class="encrypt-boxes">
          <!-- Left column: Message + Session Key -->
          <div class="left-column">
              <Card >
            <template #title>
              <h3>Encrypted Message</h3>
            </template>
            <template #content>
                <vue-json-pretty :data="ciphertext" />
                <small v-if="ciphertext.ciphertext">
                  ({{ byteLength(ciphertext.ciphertext) }} bytes ciphertext)
                </small>
                <br />
                <small v-if="ciphertext.nonce">
                  ({{ byteLength(ciphertext.nonce) }} bytes nonce)
                </small>
            </template>
          </Card>
            
          <div style="font-size: 24px; font-weight: bold; color: white;">+</div>
            <Card>
              <template #title>
                <h3>Session Key</h3>
              </template>
              <template #content>
                <vue-json-pretty :data="sessionKey"/>
              </template>
            </Card>
          </div>

          <!-- Right column: Ciphertext -->
          <div class="right-column">
            <Card>
            <template #title>
              <h3>Decrypted Message</h3>
            </template>
            <template #content>
              <Textarea
                v-model="decryptedMessage"
                placeholder="Decrypted message will appear here..."
                style="width: 100%"
                rows="5"
                :readonly="true"
              />
              <Message v-if="error" severity="error">Decryption failed!</Message>
            </template>
          </Card>
          </div>
        </div>

        <Button 
          label="Decrypt" 
          @click="decryptMessage" 
          style="margin-top: 20px; width: 50%"
        />
      </div>
    </TabPanel>
</TabView>

</template>

<style scoped>
#container, #container2, #container3, #container4 {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: center;
  background-color: rgb(17, 146, 193);
  border-radius: 10px;
  width: 100%;
  height: fit-content;
  margin: 0 auto;
  padding: 50px;
}

.encrypt-tab-container {
  display: flex;
  flex-direction: column;
  gap: 20px;
  width: 100%;
}

.encrypt-boxes .p-card {
  flex: 1 1 45%;
}
.encrypt-boxes {
  display: flex;
  gap: 20px;
  width: 100%;
  flex-wrap: nowrap; /* keep two columns */
  justify-content: space-between;
}

.left-column, .right-column {
  display: flex;
  flex-direction: column;
  flex: 1 1 45%;
}

.secrets-grid {
  display: grid;
  grid-template-columns: 1fr 1fr; /* 2 equal columns */
  gap: 20px;
  margin-top: 20px;
}

.secrets-grid .full-row {
  grid-column: 1 / -1; /* span both columns */
}

.p-card {
  width: 100%;
  margin: 20px auto;
}

h3 {
  margin: 0;
}
</style>
