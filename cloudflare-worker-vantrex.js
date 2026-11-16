const PROJECT_ID = "gcash-d6296";


const FIREBASE_API_KEY =
  "AIzaSyDkmjf-bp60OikO8l8YLIs2HXd5y1dQlXA";


const jsonHeaders = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store"
};


function json(
  data,
  status = 200,
  extraHeaders = {}
) {

  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        ...jsonHeaders,
        ...extraHeaders
      }
    }
  );

}


function corsHeaders() {

  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400"
  };

}


function withCors(response) {

  const headers =
    new Headers(
      response.headers
    );

  for (
    const [key, value]
    of Object.entries(
      corsHeaders()
    )
  ) {

    headers.set(
      key,
      value
    );

  }

  return new Response(
    response.body,
    {
      status:
        response.status,

      statusText:
        response.statusText,

      headers
    }
  );

}


/* =========================================================
   PAYMONGO
   ========================================================= */

const PAYMONGO_API_BASE = "https://api.paymongo.com/v1";

function base64ToBytes(value) {
  const normalized = String(value || "")
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .replace(/\s/g, "");

  const padded =
    normalized +
    "=".repeat((4 - (normalized.length % 4)) % 4);

  const binary = atob(padded);
  const output = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    output[i] = binary.charCodeAt(i);
  }

  return output;
}

function bytesToBase64(bytes) {
  const array =
    bytes instanceof Uint8Array
      ? bytes
      : new Uint8Array(bytes);

  let binary = "";

  for (let i = 0; i < array.length; i++) {
    binary += String.fromCharCode(array[i]);
  }

  return btoa(binary);
}

function requirePayMongoSecret(env) {
  if (!env.PAYMONGO_SECRET_KEY) {
    throw new Error("PAYMONGO_SECRET_KEY secret is missing.");
  }

  return String(env.PAYMONGO_SECRET_KEY).trim();
}

function payMongoHeaders(env, contentType = true) {
  const secret = requirePayMongoSecret(env);

  const headers = {
    Accept: "application/json",
    Authorization:
      "Basic " + btoa(`${secret}:`)
  };

  if (contentType) {
    headers["Content-Type"] = "application/json";
  }

  return headers;
}

async function payMongoRequest(
  env,
  path,
  options = {}
) {
  const response = await fetch(
    `${PAYMONGO_API_BASE}${path}`,
    {
      ...options,
      headers: {
        ...payMongoHeaders(env, options.body !== undefined),
        ...(options.headers || {})
      }
    }
  );

  const text = await response.text();

  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  if (!response.ok) {
    const message =
      data?.errors?.[0]?.detail ||
      data?.errors?.[0]?.code ||
      data?.message ||
      text.slice(0, 500) ||
      `PayMongo HTTP ${response.status}`;

    const error = new Error(
      `PayMongo HTTP ${response.status}: ${message}`
    );

    Object.defineProperty(error, "status", {
      value: response.status,
      writable: true,
      configurable: true
    });

    Object.defineProperty(error, "paymongo", {
  value: data,
  writable: true,
  configurable: true
});

    throw error;
  }

  return data;
}

async function hmacSha256Hex(
  secret,
  value
) {
  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );

  const signature =
    new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(value)
      )
    );

  return Array.from(signature)
    .map(
      byte =>
        byte.toString(16).padStart(2, "0")
    )
    .join("");
}

function constantTimeEqual(
  a,
  b
) {
  const left = String(a || "");
  const right = String(b || "");

  if (left.length !== right.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < left.length; i++) {
    result |=
      left.charCodeAt(i) ^
      right.charCodeAt(i);
  }

  return result === 0;
}

function parsePayMongoSignature(
  header
) {
  const output = {};

  for (
    const part of String(header || "").split(",")
  ) {
    const index = part.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key =
      part.slice(0, index).trim();

    const value =
      part.slice(index + 1).trim();

    if (key) {
      output[key] = value;
    }
  }

  return output;
}

async function verifyPayMongoWebhook(
  env,
  rawBody,
  signatureHeader
) {
  const secret =
    String(env.PAYMONGO_WEBHOOK_SECRET || "").trim();

  if (!secret) {
    throw new Error(
      "PAYMONGO_WEBHOOK_SECRET secret is missing."
    );
  }

  const parsed =
    parsePayMongoSignature(
      signatureHeader
    );

  const timestamp =
    parsed.t || "";

  const testSignature =
    parsed.te || "";

  const liveSignature =
    parsed.li || "";

  if (
    !timestamp ||
    (!testSignature && !liveSignature)
  ) {
    return false;
  }

  const signedPayload =
    `${timestamp}.${rawBody}`;

  const expected =
    await hmacSha256Hex(
      secret,
      signedPayload
    );

  return (
    (testSignature &&
      constantTimeEqual(
        expected,
        testSignature
      )) ||
    (liveSignature &&
      constantTimeEqual(
        expected,
        liveSignature
      ))
  );
}

/* =========================================================
   FIRESTORE
   ========================================================= */

function firestoreValue(value) {

  if (
    value === null ||
    value === undefined
  ) {

    return {
      nullValue: null
    };

  }

  if (
    typeof value ===
    "string"
  ) {

    return {
      stringValue: value
    };

  }

  if (
    typeof value ===
    "boolean"
  ) {

    return {
      booleanValue: value
    };

  }

  if (
    typeof value ===
    "number"
  ) {

    return Number.isInteger(
      value
    )
      ? {
          integerValue:
            String(value)
        }
      : {
          doubleValue:
            value
        };

  }

  if (
    value instanceof Date
  ) {

    return {
      timestampValue:
        value.toISOString()
    };

  }

  if (
    Array.isArray(value)
  ) {

    return {
      arrayValue: {
        values:
          value.map(
            firestoreValue
          )
      }
    };

  }

  if (
    typeof value ===
    "object"
  ) {

    const fields = {};

    for (
      const [key, item]
      of Object.entries(value)
    ) {

      fields[key] =
        firestoreValue(item);

    }

    return {
      mapValue: {
        fields
      }
    };

  }

  return {
    stringValue:
      String(value)
  };

}


function firestoreDocument(
  object
) {

  const fields = {};

  for (
    const [key, value]
    of Object.entries(object)
  ) {

    fields[key] =
      firestoreValue(value);

  }

  return {
    fields
  };

}


function firestoreDocToObject(
  document
) {

  if (
    !document?.fields
  ) {

    return {};

  }

  function decode(value) {

    if (!value) {
      return null;
    }

    if (
      "stringValue" in value
    ) {

      return value.stringValue;

    }

    if (
      "integerValue" in value
    ) {

      return Number(
        value.integerValue
      );

    }

    if (
      "doubleValue" in value
    ) {

      return Number(
        value.doubleValue
      );

    }

    if (
      "booleanValue" in value
    ) {

      return value.booleanValue;

    }

    if (
      "nullValue" in value
    ) {

      return null;

    }

    if (
      "timestampValue" in value
    ) {

      return value.timestampValue;

    }

    if (
      "referenceValue" in value
    ) {

      return value.referenceValue;

    }

    if (
      "arrayValue" in value
    ) {

      return (
        value.arrayValue.values ||
        []
      ).map(
        decode
      );

    }

    if (
      "mapValue" in value
    ) {

      const object = {};

      for (
        const [key, child]
        of Object.entries(
          value.mapValue.fields ||
          {}
        )
      ) {

        object[key] =
          decode(child);

      }

      return object;

    }

    return null;

  }

  const output = {};

  for (
    const [key, value]
    of Object.entries(
      document.fields
    )
  ) {

    output[key] =
      decode(value);

  }

  return output;

}


let serviceAccountCache =
  null;


let firestoreTokenCache = {
  accessToken: null,
  expiresAt: 0
};


function getServiceAccount(
  env
) {

  if (
    serviceAccountCache
  ) {

    return serviceAccountCache;

  }

  if (
    !env.FIREBASE_SERVICE_ACCOUNT_JSON
  ) {

    throw new Error(
      "FIREBASE_SERVICE_ACCOUNT_JSON secret is missing."
    );

  }

  const serviceAccount =
    JSON.parse(
      env.FIREBASE_SERVICE_ACCOUNT_JSON
    );

  // LINISIN ANG PRIVATE KEY PARA IWASAN ANG FIREBASE AUTH ERROR
  if (serviceAccount.private_key) {
    serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
  }

  if (
    !serviceAccount.client_email ||
    !serviceAccount.private_key
  ) {

    throw new Error(
      "Invalid Firebase service account JSON."
    );

  }

  serviceAccountCache =
    serviceAccount;

  return serviceAccount;

}

function pemToDer(pem) {
  const base64 = String(pem || "")
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");

  return base64ToBytes(base64);
}

function b64url(bytes) {

  const array =
    bytes instanceof Uint8Array
      ? bytes
      : new Uint8Array(bytes);

  let binary = "";

  for (
    let i = 0;
    i < array.length;
    i++
  ) {

    binary += String.fromCharCode(
      array[i]
    );

  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

}


function b64urlString(
  value
) {

  return b64url(
    new TextEncoder().encode(
      value
    )
  );

}


async function getGoogleAccessToken(
  env
) {

  const now =
    Math.floor(
      Date.now() / 1000
    );

  if (
    firestoreTokenCache.accessToken &&
    firestoreTokenCache.expiresAt >
      now + 60
  ) {

    return firestoreTokenCache.accessToken;

  }

  const serviceAccount =
    getServiceAccount(env);

  const header =
    b64urlString(
      JSON.stringify({
        alg: "RS256",
        typ: "JWT"
      })
    );

  const payload = {

    iss:
      serviceAccount.client_email,

    sub:
      serviceAccount.client_email,

    aud:
      "https://oauth2.googleapis.com/token",

    iat:
      now,

    exp:
      now + 3600,

    scope:
      "https://www.googleapis.com/auth/datastore"

  };

  const unsigned =
    `${header}.${b64urlString(
      JSON.stringify(payload)
    )}`;

  const key =
    await crypto.subtle.importKey(
      "pkcs8",
      pemToDer(
        serviceAccount.private_key
      ),
      {
        name:
          "RSASSA-PKCS1-v1_5",

        hash:
          "SHA-256"
      },
      false,
      ["sign"]
    );

  const signature =
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      key,
      new TextEncoder().encode(
        unsigned
      )
    );

  const response =
    await fetch(
      "https://oauth2.googleapis.com/token",
      {

        method:
          "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body:
          "grant_type=" +
          encodeURIComponent(
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
          ) +
          "&assertion=" +
          encodeURIComponent(
            `${unsigned}.${b64url(
              signature
            )}`
          )

      }
    );

  const text =
    await response.text();

  if (
    !response.ok
  ) {

    throw new Error(
      `Google OAuth error ${response.status}: ${text.slice(
        0,
        500
      )}`
    );

  }

  const data =
    JSON.parse(text);

  firestoreTokenCache = {

    accessToken:
      data.access_token,

    expiresAt:
      now +
      Number(
        data.expires_in ||
        3600
      )

  };

  return data.access_token;

}


async function firestoreRequest(
  env,
  path,
  options = {}
) {

  const token =
    await getGoogleAccessToken(
      env
    );

  const response =
    await fetch(
      `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${path}`,
      {

        ...options,

        headers: {

          Authorization:
            `Bearer ${token}`,

          "Content-Type":
            "application/json",

          ...(options.headers ||
            {})

        }

      }
    );

  const text =
    await response.text();

  let data = null;

  try {

    data =
      text
        ? JSON.parse(text)
        : null;

  } catch {

    data = {
      raw: text
    };

  }

  if (
    !response.ok
  ) {

    const error =
      new Error(
        `Firestore ${response.status}: ${JSON.stringify(
          data
        ).slice(0, 800)}`
      );

    Object.defineProperty(
      error,
      "status",
      {
        value:
          response.status,

        writable:
          true,

        configurable:
          true
      }
    );

    throw error;

  }

  return data;

}


async function firestoreGet(
  env,
  path
) {

  try {

    return await firestoreRequest(
      env,
      path,
      {
        method:
          "GET"
      }
    );

  } catch (error) {

    if (
      error?.status ===
      404
    ) {

      return null;

    }

    throw error;

  }

}


async function firestoreCommit(
  env,
  writes
) {

  const token =
    await getGoogleAccessToken(
      env
    );

  const response =
    await fetch(
      `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`,
      {

        method:
          "POST",

        headers: {

          Authorization:
            `Bearer ${token}`,

          "Content-Type":
            "application/json"

        },

        body:
          JSON.stringify({
            writes
          })

      }
    );

  const text =
    await response.text();

  let data = null;

  try {

    data =
      text
        ? JSON.parse(text)
        : null;

  } catch {

    data = {
      raw: text
    };

  }

  if (
    !response.ok
  ) {

    console.error(
      "FIRESTORE COMMIT FAILED:",
      {
        status: response.status,
        statusText: response.statusText,
        body: data
      }
    );

    throw new Error(
      `Firestore commit ${response.status}: ${JSON.stringify(
        data
      ).slice(0, 2000)}`
    );

  }

  return data;

}

/* =========================================================
   FIRESTORE TRANSACTION HELPERS
   ========================================================= */

async function firestoreBeginTransaction(env) {

  const token =
    await getGoogleAccessToken(env);

  const response =
    await fetch(
      `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:beginTransaction`,
      {
        method: "POST",

        headers: {
          Authorization:
            `Bearer ${token}`,

          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          options: {
            readWrite: {}
          }
        })
      }
    );

  const text =
    await response.text();

  let data = null;

  try {
    data =
      text
        ? JSON.parse(text)
        : null;
  } catch {
    data = null;
  }

  if (!response.ok) {

    throw new Error(
      `Firestore begin transaction ${response.status}: ${text.slice(0,800)}`
    );

  }

  if (!data?.transaction) {

    throw new Error(
      "Firestore transaction token was not returned."
    );

  }

  return data.transaction;
}


async function firestoreBatchGet(
  env,
  documents,
  transaction
) {

  const token =
    await getGoogleAccessToken(env);

  const response =
    await fetch(
      `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:batchGet`,
      {
        method: "POST",

        headers: {
          Authorization:
            `Bearer ${token}`,

          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          documents,
          transaction
        })
      }
    );

  const text =
    await response.text();

  let data = null;

  try {
    data =
      text
        ? JSON.parse(text)
        : null;
  } catch {
    data = null;
  }

  if (!response.ok) {

    throw new Error(
      `Firestore batch get ${response.status}: ${text.slice(0,800)}`
    );

  }

  return data;
}


async function firestoreCommitTransaction(
  env,
  writes,
  transaction
) {

  const token =
    await getGoogleAccessToken(env);

  const response =
    await fetch(
      `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`,
      {
        method: "POST",

        headers: {
          Authorization:
            `Bearer ${token}`,

          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          writes,
          transaction
        })
      }
    );

  const text =
    await response.text();

  let data = null;

  try {
    data =
      text
        ? JSON.parse(text)
        : null;
  } catch {
    data = null;
  }

  if (!response.ok) {

    throw new Error(
      `Firestore transaction commit ${response.status}: ${text.slice(0,1000)}`
    );

  }

  return data;
}

/* =========================================================
   SUPABASE AUTH (Pinalitan ang Firebase)
   ========================================================= */

async function verifyFirebaseIdToken(
  env,
  request
) {
  const authorization =
    request.headers.get(
      "Authorization"
    ) || "";

  if (
    !authorization.startsWith(
      "Bearer "
    )
  ) {
    throw new Error(
      "Missing Supabase Authorization token."
    );
  }

  const token =
    authorization
      .slice(7)
      .trim();

  if (!token) {
    throw new Error(
      "Missing Supabase ID token."
    );
  }

  try {
    // I-decode ang Supabase JWT para makuha ang user ID (sub)
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    
    const payload = JSON.parse(jsonPayload);
    if (!payload.sub) {
      throw new Error("Invalid token payload");
    }

    return {
      uid: payload.sub,
      email: payload.email || "",
      displayName: payload.user_metadata?.username || ""
    };
  } catch (e) {
    throw new Error("Invalid or expired Supabase ID token.");
  }
}


/* =========================================================
   RECHARGE HELPERS
   ========================================================= */

function makeOrderId() {

  return (
    `NR${Date.now()}` +
    crypto
      .randomUUID()
      .replace(/-/g, "")
      .slice(0, 16)
  );

}


function amountNumber(value) {

  const number =
    Number(value);

  return Number.isFinite(
    number
  )
    ? Math.round(
        number * 100
      ) / 100
    : null;

}


function isValidAmount(
  amount
) {

  return (
    amount !== null &&
    amount >= 1 &&
    amount <= 999000
  );

}


function transactionEntry(
  orderId,
  amount
) {

  return {

    type:
      "Recharge",

    amount,

    date:
      new Date().toLocaleString(
        "en-PH",
        {
          timeZone:
            "Asia/Manila",

          year:
            "numeric",

          month:
            "2-digit",

          day:
            "2-digit",

          hour:
            "2-digit",

          minute:
            "2-digit",

          second:
            "2-digit"
        }
      ),

    orderId,

    method:
      "PayMongo",

    currency:
      "PHP"

  };

}


async function createPendingRecharge(
  env,
  orderId,
  uid,
  amount
) {

  const id =
    encodeURIComponent(
      orderId
    );

  const name =
    `projects/${PROJECT_ID}/databases/(default)/documents/Recharges/${id}`;

  await firestoreCommit(
    env,
    [
      {

        update: {

          name,

          fields:
            firestoreDocument({

              uid,

              amount,

              currency:
                "PHP",

              country:
                "PH",

              status:
                "PENDING",

              orderId,

              provider:
                "PayMongo",

              createdAt:
                new Date().toISOString()

            }).fields

        },

        currentDocument: {
          exists:
            false
        }

      }
    ]
  );

}


async function markRechargeFailed(
  env,
  orderId,
  reason
) {

  const id =
    encodeURIComponent(
      orderId
    );

  const existing =
    await firestoreGet(
      env,
      `Recharges/${id}`
    );

  if (!existing) {
    return;
  }

  const name =
    `projects/${PROJECT_ID}/databases/(default)/documents/Recharges/${id}`;

  try {

    await firestoreCommit(
      env,
      [

        {

          update: {

            name,

            fields:
              firestoreDocument({

                status:
                  "FAILED",

                failureReason:
                  String(
                    reason ||
                      "PayMongo payment request failed"
                  ).slice(
                    0,
                    500
                  ),

                updatedAt:
                  new Date().toISOString()

              }).fields

          },

          updateMask: {

            fieldPaths: [

              "status",
              "failureReason",
              "updatedAt"

            ]

          },

          currentDocument: {

            updateTime:
              existing.updateTime

          }

        }

      ]
    );

  } catch {}

}


/* =========================================================
   CREATE PAYMONGO PAYMENT
   ========================================================= */

async function createPayMongoPayment(
  env,
  uid,
  amount
) {
  const orderId = makeOrderId();

  await createPendingRecharge(
    env,
    orderId,
    uid,
    amount
  );

  try {
    const paymentIntentResponse =
      await payMongoRequest(
        env,
        "/payment_intents",
        {
          method: "POST",
          body: JSON.stringify({
            data: {
              attributes: {
                amount: Math.round(amount * 100),
                currency: "PHP",
                payment_method_allowed: ["qrph"],
                description:
                  `Novarise Recharge ${orderId}`,
                metadata: {
                  orderId,
                  uid
                }
              }
            }
          })
        }
      );

    const intent =
      paymentIntentResponse?.data;

    const paymentIntentId =
      String(intent?.id || "");

    const clientKey =
      String(
        intent?.attributes?.client_key || ""
      );

    if (!paymentIntentId || !clientKey) {
      throw new Error(
        "PayMongo did not return a valid payment intent."
      );
    }

    const paymentMethodResponse =
      await payMongoRequest(
        env,
        "/payment_methods",
        {
          method: "POST",
          body: JSON.stringify({
            data: {
              attributes: {
                type: "qrph"
              }
            }
          })
        }
      );

    const paymentMethod =
      paymentMethodResponse?.data;

    const paymentMethodId =
      String(paymentMethod?.id || "");

    if (!paymentMethodId) {
      throw new Error(
        "PayMongo did not return a QR Ph payment method."
      );
    }

    const attachResponse =
      await payMongoRequest(
        env,
        `/payment_intents/${encodeURIComponent(
          paymentIntentId
        )}/attach`,
        {
          method: "POST",
          body: JSON.stringify({
            data: {
              attributes: {
                payment_method:
                  paymentMethodId,
                client_key:
                  clientKey
              }
            }
          })
        }
      );

    const attachedIntent =
      attachResponse?.data ||
      intent;

    const attributes =
      attachedIntent?.attributes || {};

    const imageUrl =
      attributes?.next_action?.code?.image_url ||
      attributes?.next_action?.qr_code?.image_url ||
      "";

    if (!imageUrl) {
      throw new Error(
        "PayMongo did not return the QR Ph image URL."
      );
    }

    const pending =
      await firestoreGet(
        env,
        `Recharges/${encodeURIComponent(
          orderId
        )}`
      );

    if (pending) {
      const name =
        `projects/${PROJECT_ID}/databases/(default)/documents/Recharges/${encodeURIComponent(
          orderId
        )}`;

      await firestoreCommit(
        env,
        [
          {
            update: {
              name,
              fields:
                firestoreDocument({
                  providerOrderId:
                    paymentIntentId,

                  paymentIntentId,

                  paymentMethodId,

                  qrCode:
                    imageUrl,

                  qrCodeImageUrl:
                    imageUrl,

                  paymentMethod:
                    "QRPH",

                  providerStatus:
                    attributes.status ||
                    "awaiting_next_action",

                  updatedAt:
                    new Date().toISOString()
                }).fields
            },
            updateMask: {
              fieldPaths: [
                "providerOrderId",
                "paymentIntentId",
                "paymentMethodId",
                "qrCode",
                "qrCodeImageUrl",
                "paymentMethod",
                "providerStatus",
                "updatedAt"
              ]
            },
            currentDocument: {
              updateTime:
                pending.updateTime
            }
          }
        ]
      );
    }

    return {
      success: true,

      qrCode:
        imageUrl,

      qrCodeImageUrl:
        imageUrl,

      orderId,

      paymentIntentId,

      paymentMethodId,

      status:
        attributes.status ||
        "awaiting_next_action",

      paymentMethod:
        "QRPH"
    };
  } catch (error) {
    await markRechargeFailed(
      env,
      orderId,
      error?.message ||
        "PayMongo payment request failed"
    );

    throw error;
  }
}

/* =========================================================
   CREATE PAYMENT ENDPOINT
   ========================================================= */

async function handleCreatePayment(
  env,
  request
) {

  const user =
    await verifyFirebaseIdToken(
      env,
      request
    );

  const payload =
    await request
      .json()
      .catch(
        () => ({})
      );

  const amount =
    amountNumber(
      payload.amount
    );


  if (
    !isValidAmount(
      amount
    )
  ) {

    return json(
      {

        error:
          "INVALID_AMOUNT",

        message:
          "Recharge amount must be between PHP 1 and PHP 999,000."

      },
      400
    );

  }


  const payment =
  await createPayMongoPayment(
    env,
    user.uid,
    amount
  );

  return json({

    success:
      true,

    ...payment

  });

}


/* =========================================================
   PAYMONGO PAYMENT INTENT INQUIRY
   ========================================================= */

async function queryPayMongoPaymentIntent(
  env,
  paymentIntentId
) {
  if (!paymentIntentId) {
    throw new Error(
      "Recharge record has no PayMongo payment intent ID."
    );
  }

  const response =
    await payMongoRequest(
      env,
      `/payment_intents/${encodeURIComponent(
        paymentIntentId
      )}`,
      {
        method: "GET"
      }
    );

  const result =
    response?.data;

  if (!result?.id) {
    throw new Error(
      "PayMongo payment intent response was empty."
    );
  }

  if (
    String(result.id) !==
    String(paymentIntentId)
  ) {
    throw new Error(
      "PayMongo returned a different payment intent ID."
    );
  }

  const attributes =
    result.attributes || {};

  return {
    code: "SUCCESS",
    message: "",
    data: {
      paymentIntentId:
        result.id,

      status:
        attributes.status ||
        "PENDING",

      totalAmount:
        Number(attributes.amount || 0) / 100,

      currency:
        attributes.currency ||
        "PHP",

      tradeToken:
        result.id,

      completeTime:
        attributes.updated_at
          ? new Date(
              Number(attributes.updated_at) * 1000
            ).toISOString()
          : new Date().toISOString(),

      metadata:
        attributes.metadata || {},

      raw:
        result
    }
  };
}

/* =========================================================
   CREDIT SUCCESSFUL RECHARGE
   ========================================================= */

async function creditSuccessfulRecharge(
  env,
  rechargeDocument,
  callbackData
) {

  const recharge =
    firestoreDocToObject(
      rechargeDocument
    );


  if (!recharge.uid) {

    throw new Error(
      "Recharge record has no uid."
    );

  }


  const callbackAmount =
    amountNumber(
      callbackData?.totalAmount
    );

  const storedAmount =
    amountNumber(
      recharge.amount
    );


  if (
    callbackAmount === null ||
    storedAmount === null ||
    Math.abs(
      callbackAmount -
      storedAmount
    ) > 0.001
  ) {

    throw new Error(
      "Recharge amount mismatch."
    );

  }


  if (
    (
      callbackData.currency ||
      "PHP"
    ).toUpperCase() !==
    (
      recharge.currency ||
      "PHP"
    ).toUpperCase()
  ) {

    throw new Error(
      "Recharge currency mismatch."
    );

  }


  if (
    recharge.status ===
    "SUCCESS"
  ) {

    return;

  }


  const orderId =
    encodeURIComponent(
      recharge.orderId
    );


  const rechargeName =
    `projects/${PROJECT_ID}/databases/(default)/documents/Recharges/${orderId}`;


  const userName =
    `projects/${PROJECT_ID}/databases/(default)/documents/Users/${encodeURIComponent(
      recharge.uid
    )}`;


  const rechargeWrite = {

    update: {

      name:
        rechargeName,

      fields:
        firestoreDocument({

          status:
            "SUCCESS",

          completedAt:
            callbackData?.completeTime ||
            new Date().toISOString(),

          providerTradeToken:
            callbackData?.tradeToken ||
            "",

          providerStatus:
            callbackData?.status ||
            "SUCCESS",

          updatedAt:
            new Date().toISOString()

        }).fields

    },

    updateMask: {

      fieldPaths: [

        "status",
        "completedAt",
        "providerTradeToken",
        "providerStatus",
        "updatedAt"

      ]

    },

    currentDocument: {

      updateTime:
        rechargeDocument.updateTime

    }

  };


  const userTransformWrite = {

    transform: {

      document:
        userName,

      fieldTransforms: [

        {

          fieldPath:
            "balance",

          increment:
            firestoreValue(
              storedAmount
            )

        },

        {

          fieldPath:
            "transactions",

          appendMissingElements: {

            values: [

              firestoreValue(
                transactionEntry(
                  recharge.orderId,
                  storedAmount
                )
              )

            ]

          }

        }

      ]

    }

  };


  await firestoreCommit(
    env,
    [
      rechargeWrite,
      userTransformWrite
    ]
  );

}


/* =========================================================
   RECHARGE STATUS / TRANSACTION INQUIRY
   ========================================================= */

async function handleRechargeStatus(
  env,
  request
) {
  const user =
    await verifyFirebaseIdToken(
      env,
      request
    );

  const url =
    new URL(request.url);

  const orderId =
    url.searchParams.get("orderId") || "";

  if (
    !/^[A-Za-z0-9_-]{1,64}$/.test(
      orderId
    )
  ) {
    return json(
      {
        error:
          "INVALID_ORDER_ID",
        message:
          "Invalid recharge order ID."
      },
      400
    );
  }

  const document =
    await firestoreGet(
      env,
      `Recharges/${encodeURIComponent(
        orderId
      )}`
    );

  if (!document) {
    return json(
      {
        error:
          "NOT_FOUND",
        message:
          "Recharge order was not found."
      },
      404
    );
  }

  const recharge =
    firestoreDocToObject(document);

  if (recharge.uid !== user.uid) {
    return json(
      {
        error:
          "FORBIDDEN",
        message:
          "This recharge order does not belong to the current user."
      },
      403
    );
  }

  if (
    recharge.status ===
    "SUCCESS"
  ) {
    return json({
      success: true,
      orderId,
      status: "SUCCESS",
      amount:
        Number(recharge.amount || 0),
      currency:
        recharge.currency || "PHP",
      source: "firestore"
    });
  }

  let query;

  try {
    query =
      await queryPayMongoPaymentIntent(
        env,
        recharge.paymentIntentId
      );
  } catch (error) {
    console.error(
      "PayMongo payment intent query error:",
      error
    );

    return json(
      {
        error:
          "PAYMONGO_QUERY_FAILED",
        message:
          error?.message ||
          "Unable to query PayMongo payment status."
      },
      502
    );
  }

   const providerData =
  /** @type {any} */ (
    query.data || {}
  );

  const rawStatus =
    String(
      providerData.status ||
      "PENDING"
    );

  const providerStatus =
    rawStatus.toUpperCase();

  const providerAmount =
    amountNumber(
      providerData.totalAmount
    );

  const storedAmount =
    amountNumber(
      recharge.amount
    );

  const providerCurrency =
    String(
      providerData.currency ||
      "PHP"
    ).toUpperCase();

  const storedCurrency =
    String(
      recharge.currency ||
      "PHP"
    ).toUpperCase();

  if (
    providerAmount === null ||
    storedAmount === null ||
    Math.abs(
      providerAmount -
      storedAmount
    ) > 0.001
  ) {
    console.error(
      "PayMongo amount mismatch",
      {
        orderId,
        providerAmount,
        storedAmount
      }
    );

    return json(
      {
        error:
          "PAYMENT_AMOUNT_MISMATCH",
        message:
          "PayMongo payment amount does not match the recharge amount."
      },
      409
    );
  }

  if (
    providerCurrency !==
    storedCurrency
  ) {
    console.error(
      "PayMongo currency mismatch",
      {
        orderId,
        providerCurrency,
        storedCurrency
      }
    );

    return json(
      {
        error:
          "PAYMENT_CURRENCY_MISMATCH",
        message:
          "PayMongo payment currency does not match the recharge currency."
      },
      409
    );
  }

  if (
  providerStatus ===
    "SUCCEEDED" ||
  providerStatus ===
    "SUCCESS"
) {

  const latest =
    await firestoreGet(
      env,
      `Recharges/${encodeURIComponent(
        orderId
      )}`
    );

  if (latest) {

    const latestData =
      firestoreDocToObject(
        latest
      );

    /*
      IMPORTANT:

      PayMongo payment is confirmed,
      but DO NOT credit the user's balance here.

      The recharge must remain PENDING
      until the admin manually approves it.
    */

    if (
      latestData.status !==
      "APPROVED"
    ) {

      const name =
        `projects/${PROJECT_ID}/databases/(default)/documents/Recharges/${encodeURIComponent(
          orderId
        )}`;

      try {

        await firestoreCommit(
          env,
          [
            {
              update: {
                name,

                fields:
                  firestoreDocument({

                    status:
                      "PENDING",

                    updatedAt:
                      new Date().toISOString(),

                    providerStatus,

                    providerMessage:
                      "PayMongo payment confirmed. Waiting for admin approval."

                  }).fields
              }
            }
          ]
        );

      } catch (error) {

        console.error(
          "Unable to update recharge status:",
          error
        );

      }

    }

  }

  return json({
    success: true,

    orderId,

    status:
      "PENDING",

    amount:
      storedAmount,

    currency:
      storedCurrency,

    source:
      "paymongo-paymentIntent"
  });
}

  if (
    providerStatus ===
      "FAILED" ||
    providerStatus ===
      "CANCELLED"
  ) {
    const latest =
      await firestoreGet(
        env,
        `Recharges/${encodeURIComponent(
          orderId
        )}`
      );

    if (latest) {
      const latestData =
        firestoreDocToObject(
          latest
        );

      if (
        latestData.status !==
        "SUCCESS"
      ) {
        const name =
          `projects/${PROJECT_ID}/databases/(default)/documents/Recharges/${encodeURIComponent(
            orderId
          )}`;

        try {
          await firestoreCommit(
            env,
            [
              {
                update: {
                  name,
                  fields:
                    firestoreDocument({
                      status:
                        providerStatus ===
                        "CANCELLED"
                          ? "CLOSED"
                          : "FAILED",

                      updatedAt:
                        new Date().toISOString(),

                      providerStatus,

                      providerMessage:
                        "PayMongo payment was not completed."
                    }).fields
                },

                updateMask: {
                  fieldPaths: [
                    "status",
                    "updatedAt",
                    "providerStatus",
                    "providerMessage"
                  ]
                },

                currentDocument: {
                  updateTime:
                    latest.updateTime
                }
              }
            ]
          );
        } catch (error) {
          console.error(
            "Unable to save PayMongo failed status:",
            error
          );
        }
      }
    }

    return json({
      success: true,
      orderId,
      status:
        providerStatus ===
        "CANCELLED"
          ? "CLOSED"
          : "FAILED",
      amount: storedAmount,
      currency: storedCurrency,
      source:
        "paymongo-paymentIntent"
    });
  }

  return json({
    success: true,
    orderId,
    status: providerStatus,
    amount: storedAmount,
    currency: storedCurrency,
    source:
      "paymongo-paymentIntent"
  });
}

/* =========================================================
   PAYMONGO WEBHOOK
   ========================================================= */

async function handlePayMongoWebhook(
  env,
  request
) {
  const rawBody =
    await request.text();

  const signature =
    request.headers.get(
      "PayMongo-Signature"
    ) ||
    request.headers.get(
      "Paymongo-Signature"
    ) ||
    "";

  const valid =
    await verifyPayMongoWebhook(
      env,
      rawBody,
      signature
    );

  if (!valid) {
    return json(
      {
        code:
          "INVALID_SIGNATURE",
        message:
          "Invalid PayMongo webhook signature."
      },
      401
    );
  }

  let event;

  try {
    event =
      JSON.parse(rawBody);
  } catch {
    return json(
      {
        code:
          "INVALID_BODY",
        message:
          "Invalid JSON."
      },
      400
    );
  }

  const eventAttributes =
    event?.data?.attributes ||
    {};

  const eventType =
    String(
      eventAttributes.type ||
      ""
    ).toLowerCase();

  const eventData =
    eventAttributes.data ||
    {};

  const eventDataAttributes =
    eventData.attributes ||
    {};

  let paymentIntentId =
    String(
      eventDataAttributes.payment_intent_id ||
      eventDataAttributes.payment_intent?.id ||
      eventDataAttributes.paymentIntentId ||
      ""
    );

  let orderId =
    String(
      eventDataAttributes?.metadata?.orderId ||
      eventDataAttributes?.metadata?.order_id ||
      ""
    );

  let rechargeDocument = null;

  if (
    paymentIntentId
  ) {
    /*
     * The Payment Intent metadata contains our
     * internal order ID. Retrieve the intent so
     * the webhook does not depend on the exact
     * shape of the payment event.
     */
    try {
      const intentResponse =
        await payMongoRequest(
          env,
          `/payment_intents/${encodeURIComponent(
            paymentIntentId
          )}`,
          {
            method: "GET"
          }
        );

      const intent =
        intentResponse?.data;

      const intentAttributes =
        intent?.attributes || {};

      const intentMetadata =
        intentAttributes.metadata ||
        {};

      orderId =
        orderId ||
        String(
          intentMetadata.orderId ||
          intentMetadata.order_id ||
          ""
        );
    } catch (error) {
      console.error(
        "Unable to retrieve PayMongo payment intent from webhook:",
        error
      );
    }
  }

  /*
   * Some PayMongo webhook payloads expose the
   * payment intent metadata directly.
   */
  if (!orderId) {
    orderId =
      String(
        eventDataAttributes?.metadata?.orderId ||
        eventDataAttributes?.metadata?.order_id ||
        event?.data?.attributes?.metadata?.orderId ||
        ""
      );
  }

  /*
   * If only the Payment Intent ID is present,
   * retrieve it and read metadata again.
   */
  if (
    !orderId &&
    paymentIntentId
  ) {
    try {
      const intentResponse =
        await payMongoRequest(
          env,
          `/payment_intents/${encodeURIComponent(
            paymentIntentId
          )}`,
          {
            method: "GET"
          }
        );

      const intent =
        intentResponse?.data;

      orderId =
        String(
          intent?.attributes?.metadata?.orderId ||
          ""
        );
    } catch {}
  }

  if (
    !/^[A-Za-z0-9_-]{1,64}$/.test(
      orderId
    )
  ) {
    /*
     * Acknowledge unrelated events so PayMongo
     * does not repeatedly retry a webhook that
     * belongs to another object.
     */
    return json({
      code:
        "SUCCESS",
      message:
        "Webhook received."
    });
  }

  rechargeDocument =
    await firestoreGet(
      env,

      `Recharges/${encodeURIComponent(
        orderId
      )}`
    );

  if (!rechargeDocument) {
    return json({
      code:
        "SUCCESS",
      message:
        "Webhook received."
    });
  }

  const recharge =
    firestoreDocToObject(
      rechargeDocument
    );
if (
  eventType ===
    "payment.paid"
) {

  /*
   * PayMongo confirms that the payment was paid.
   *
   * IMPORTANT:
   * Do NOT credit the member balance here.
   *
   * The recharge remains PENDING until
   * the admin manually approves it.
   */

  const latest =
    await firestoreGet(
      env,
      `Recharges/${encodeURIComponent(
        orderId
      )}`
    );

  if (latest) {

    const latestData =
      firestoreDocToObject(
        latest
      );

    /*
     * If admin already approved this recharge,
     * never change it back to PENDING.
     */

    if (
      latestData.status !==
        "APPROVED" &&
      latestData.status !==
        "SUCCESS"
    ) {

      const id =
        encodeURIComponent(
          orderId
        );

      const name =
        `projects/${PROJECT_ID}/databases/(default)/documents/Recharges/${id}`;

      try {

        await firestoreCommit(
          env,
          [
            {
              update: {

                name,

                fields:
                  firestoreDocument({

                    status:
                      "PENDING",

                    updatedAt:
                      new Date().toISOString(),

                    providerStatus:
                      "payment.paid",

                    providerMessage:
                      "PayMongo payment confirmed. Waiting for admin approval."

                  }).fields
              },

              updateMask: {

                fieldPaths: [
                  "status",
                  "updatedAt",
                  "providerStatus",
                  "providerMessage"
                ]

              },

              currentDocument: {

                updateTime:
                  latest.updateTime

              }

            }
          ]
        );

      } catch (error) {

        console.error(
          "Unable to update PayMongo recharge webhook status:",
          error
        );

      }

    }

  }

  return json({

    code:
      "SUCCESS",

    message:
      "Payment received. Waiting for admin approval."

  });

}


if (
  eventType ===
    "payment.failed" ||
  eventType ===
    "qrph.expired"
) {

  const latest =
    await firestoreGet(
      env,
      `Recharges/${encodeURIComponent(
        orderId
      )}`
    );

  if (latest) {

    const latestData =
      firestoreDocToObject(
        latest
      );

    if (
      latestData.status !==
      "APPROVED" &&
      latestData.status !==
      "SUCCESS"
    ) {

      const id =
        encodeURIComponent(
          orderId
        );

      const name =
        `projects/${PROJECT_ID}/databases/(default)/documents/Recharges/${id}`;

      try {

        await firestoreCommit(
          env,
          [
            {
              update: {

                name,

                fields:
                  firestoreDocument({

                    status:
                      eventType ===
                      "qrph.expired"
                        ? "CLOSED"
                        : "FAILED",

                    updatedAt:
                      new Date().toISOString(),

                    providerStatus:
                      eventType,

                    providerMessage:
                      eventType ===
                      "qrph.expired"
                        ? "PayMongo QR Ph payment expired."
                        : "PayMongo payment failed."

                  }).fields
              },

              updateMask: {

                fieldPaths: [
                  "status",
                  "updatedAt",
                  "providerStatus",
                  "providerMessage"
                ]

              },

              currentDocument: {

                updateTime:
                  latest.updateTime

              }

            }
          ]
        );

      } catch (error) {

        console.error(
          "Unable to save PayMongo failed status:",
          error
        );

      }

    }

  }

  return json({

    code:
      "SUCCESS",

    message:
      "Payment status recorded."

  });

}
}

/* =========================================================
   REWARD TODAY
   ========================================================= */

async function handleRewardToday(
  env,
  request
) {

  const user =
    await verifyFirebaseIdToken(
      env,
      request
    );

  const userName =
    `projects/${PROJECT_ID}/databases/(default)/documents/Users/${encodeURIComponent(
      user.uid
    )}`;

  const rewardAmount = 10;

  const cooldownMs =
    24 * 60 * 60 * 1000;

  const transaction =
    await firestoreBeginTransaction(
      env
    );

  const result =
    await firestoreBatchGet(
      env,
      [userName],
      transaction
    );

  const found =
    result?.find(
      item =>
        item?.found?.name === userName
    );

  if (!found?.found) {

    return json(
      {
        error:
          "USER_NOT_FOUND",

        message:
          "User account was not found."
      },
      404
    );

  }

  const userData =
    firestoreDocToObject(
      found.found
    );

  const now =
    Date.now();

  const lastClaimAt =
    userData.rewardLastClaimAt
      ? new Date(
          userData.rewardLastClaimAt
        ).getTime()
      : 0;

  if (
    Number.isFinite(lastClaimAt) &&
    now <
      lastClaimAt +
        cooldownMs
  ) {

    const nextEligibleAt =
      lastClaimAt +
      cooldownMs;

    const remainingMs =
      nextEligibleAt -
      now;

    return json(
      {
        error:
          "REWARD_COOLDOWN",

        message:
          "Reward Today is not available yet.",

        nextEligibleAt:
          new Date(
            nextEligibleAt
          ).toISOString(),

        remainingMs
      },
      429
    );

  }

  const claimTime =
    new Date();

  const transactionEntry = {

    type:
      "Reward Today",

    amount:
      rewardAmount,

    date:
      claimTime.toLocaleString(
        "en-PH",
        {
          timeZone:
            "Asia/Manila",

          year:
            "numeric",

          month:
            "2-digit",

          day:
            "2-digit",

          hour:
            "2-digit",

          minute:
            "2-digit",

          second:
            "2-digit"
        }
      ),

    currency:
      "PHP"

  };

  const userWrite = {

    update: {

      name:
        userName,

      fields:
        firestoreDocument({

          rewardLastClaimAt:
            claimTime

        }).fields

    },

    updateMask: {

      fieldPaths: [
        "rewardLastClaimAt"
      ]

    },

    updateTransforms: [

      {

        fieldPath:
          "balance",

        increment:
          firestoreValue(
            rewardAmount
          )

      },

      {

        fieldPath:
          "transactions",

        appendMissingElements: {

          values: [

            firestoreValue(
              transactionEntry
            )

          ]

        }

      }

    ]

  };

  await firestoreCommitTransaction(
    env,
    [
      userWrite
    ],
    transaction
  );

  return json({

    success:
      true,

    reward:
      rewardAmount,

    message:
      "Reward Today claimed successfully.",

    nextEligibleAt:
      new Date(
        now +
        cooldownMs
      ).toISOString()

  });

}

/* =========================================================
   REWARD CODE
   ========================================================= */

async function handleRewardCode(env, request) {

  // =========================
  // VERIFY USER
  // =========================
  const user =
    await verifyFirebaseIdToken(
      env,
      request
    );


  // =========================
  // READ REQUEST
  // =========================
  const payload =
    await request
      .json()
      .catch(() => ({}));


  const rawCode =
    String(
      payload.code || ""
    ).trim();


  if (!rawCode) {

    return json(
      {
        error:
          "INVALID_CODE",

        message:
          "Please enter a reward code."
      },
      400
    );

  }


  // =========================
  // NORMALIZE CODE
  // =========================
  const code =
    rawCode.toUpperCase();


  if (
    !/^[A-Z0-9_-]{1,50}$/.test(code)
  ) {

    return json(
      {
        error:
          "INVALID_CODE",

        message:
          "Invalid reward code."
      },
      400
    );

  }


  // =========================
  // FIXED REWARD
  // =========================
  const rewardAmount = 10;


  // =========================
  // FIRESTORE PATHS
  // =========================

  // IMPORTANT:
  // firestoreGet() uses a relative path.
  //
  // Example:
  // RewardCodes/MyNovarise2026

  const codePath =
    `RewardCodes/${encodeURIComponent(
      code
    )}`;


  const userPath =
    `Users/${encodeURIComponent(
      user.uid
    )}`;


  const redemptionId =
    `${code}_${user.uid}`;


  const redemptionPath =
    `RewardRedemptions/${encodeURIComponent(
      redemptionId
    )}`;


  // =========================
  // LOAD DOCUMENTS
  // =========================

  const [
    codeDocument,
    userDocument,
    redemptionDocument
  ] = await Promise.all([

    firestoreGet(
      env,
      codePath
    ),

    firestoreGet(
      env,
      userPath
    ),

    firestoreGet(
      env,
      redemptionPath
    )

  ]);


  // =========================
  // USER MUST EXIST
  // =========================

  if (!userDocument) {

    console.log(
      "REWARD CODE USER NOT FOUND:",
      {
        uid:
          user.uid,

        userPath:
          userPath
      }
    );

    return json(
      {
        error:
          "USER_NOT_FOUND",

        message:
          "User account was not found."
      },
      404
    );

  }


  // =========================
  // CODE MUST EXIST
  // =========================

  if (!codeDocument) {

    console.log(
      "INVALID REWARD CODE:",
      {
        uid:
          user.uid,

        code:
          code,

        codePath:
          codePath
      }
    );

    return json(
      {
        error:
          "INVALID_CODE",

        message:
          "Reward code is invalid."
      },
      400
    );

  }


  // =========================
  // VALID CODE FOUND
  // =========================

  console.log(
    "VALID REWARD CODE FOUND:",
    {
      code:
        code,

      path:
        codePath
    }
  );


  // =========================
  // SAME USER CANNOT
  // REDEEM SAME CODE TWICE
  // =========================

  if (redemptionDocument) {

    console.log(
      "REWARD CODE ALREADY REDEEMED:",
      {
        uid:
          user.uid,

        code:
          code,

        redemptionPath:
          redemptionPath
      }
    );

    return json(
      {
        error:
          "CODE_ALREADY_REDEEMED",

        message:
          "You have already redeemed this reward code."
      },
      409
    );

  }


  // =========================
  // REDEMPTION TIME
  // =========================

  const redeemTime =
    new Date();


  // =========================
  // TRANSACTION HISTORY
  // =========================

  const transactionEntry = {

    type:
      "Reward Code",

    amount:
      rewardAmount,

    date:
      redeemTime.toLocaleString(
        "en-PH",
        {
          timeZone:
            "Asia/Manila",

          year:
            "numeric",

          month:
            "2-digit",

          day:
            "2-digit",

          hour:
            "2-digit",

          minute:
            "2-digit",

          second:
            "2-digit"
        }
      ),

    currency:
      "PHP",

    code:
      code

  };


  // =========================
  // FULL FIRESTORE NAMES
  // =========================

  const userName =
    `projects/${PROJECT_ID}/databases/(default)/documents/${userPath}`;


  const redemptionName =
    `projects/${PROJECT_ID}/databases/(default)/documents/${redemptionPath}`;


  // =========================
  // CREATE REDEMPTION
  // =========================

  const redemptionWrite = {

    update: {

      name:
        redemptionName,

      fields:
        firestoreDocument(
          {

            userId:
              user.uid,

            code:
              code,

            reward:
              rewardAmount,

            redeemedAt:
              redeemTime

          }
        ).fields

    },

    currentDocument: {

      exists:
        false

    }

  };


  // =========================
  // ADD ₱10 TO BALANCE
  // =========================

  const userWrite = {

    transform: {

      document:
        userName,

      fieldTransforms: [

        {

          fieldPath:
            "balance",

          increment:
            firestoreValue(
              rewardAmount
            )

        },

        {

          fieldPath:
            "transactions",

          appendMissingElements: {

            values: [

              firestoreValue(
                transactionEntry
              )

            ]

          }

        }

      ]

    }

  };


  // =========================
  // ATOMIC COMMIT
  // =========================

  try {

    await firestoreCommit(
      env,
      [
        redemptionWrite,
        userWrite
      ]
    );

  } catch (error) {

    console.error(
      "REWARD CODE COMMIT ERROR:",
      error
    );


    const errorMessage =
      String(
        error?.message || ""
      );


    if (
      errorMessage.includes(
        "ALREADY_EXISTS"
      ) ||
      errorMessage.includes(
        "already exists"
      ) ||
      errorMessage.includes(
        "FAILED_PRECONDITION"
      )
    ) {

      return json(
        {
          error:
            "CODE_ALREADY_REDEEMED",

          message:
            "You have already redeemed this reward code."
        },
        409
      );

    }


    return json(
      {
        error:
          "REWARD_CODE_COMMIT_FAILED",

        message:
          "Unable to redeem reward code. Please try again."
      },
      500
    );

  }


  // =========================
  // SUCCESS
  // =========================

  console.log(
    "REWARD CODE SUCCESS:",
    {
      uid:
        user.uid,

      code:
        code,

      reward:
        rewardAmount
    }
  );


  return json(
    {
      success:
        true,

      reward:
        rewardAmount,

      message:
        "Reward code redeemed successfully."
    }
  );

}

/* =========================================================
   ROUTER
   ========================================================= */

async function router(
  env,
  request
) {

  const rawPath =
    new URL(
      request.url
    ).pathname;

  const path =
    rawPath.replace(/^\/vantrex(?=\/|$)/, "") || "/";


  if (
    request.method ===
    "OPTIONS"
  ) {

    return new Response(
      null,
      {
        status:
          204,

        headers:
          corsHeaders()
      }
    );

  }

if (
    request.method ===
      "POST" &&
    path ===
      "/reward-today"
  ) {

    return handleRewardToday(
      env,
      request
    );

  }

if (
    request.method ===
      "POST" &&
    path ===
      "/reward-code"
  ) {

    return handleRewardCode(
      env,
      request
    );

  }

  if (
    request.method ===
      "GET" &&
    (
      path === "/" ||
      path === ""
    )
  ) {

    return json({

      ok:
        true,

      service:
        "Novarise PayMongo Worker",

      project:
        PROJECT_ID

    });

  }


  if (
    request.method ===
      "POST" &&
    path ===
      "/create-paymongo-payment"
  ) {

    return handleCreatePayment(
      env,
      request
    );

  }


  if (
    request.method ===
      "GET" &&
    path ===
      "/recharge-status"
  ) {

    return handleRechargeStatus(
      env,
      request
    );

  }


  if (
    request.method ===
      "POST" &&
    path ===
      "/paymongo-webhook"
  ) {

    return handlePayMongoWebhook(
      env,
      request
    );

  }


  return json(
    {

      error:
        "NOT_FOUND",

      message:
        "Endpoint not found."

    },
    404
  );

}


/* =========================================================
   CLOUDFLARE WORKER ENTRY
   ========================================================= */

export default {

  async fetch(
    request,
    env
  ) {

    try {

      const response =
        await router(
          env,
          request
        );

      return withCors(
        response
      );

    } catch (error) {

      console.error(
        error
      );

      return withCors(
        json(
          {

            error:
              "SERVER_ERROR",

            message:
              error?.message ||
              "Unexpected server error."

          },
          500
        )
      );

    }

  }

};
