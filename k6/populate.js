import http from 'k6/http';
import { sleep, check } from 'k6';
import encoding from 'k6/encoding';

sleep(15);

export const options = {
    stages: [
        { duration: '15s', target: 20 },
        { duration: '45s', target: 10 },
        { duration: '15s', target: 0 },
    ]
}

const accounts = JSON.parse(open("./accounts.json"));

function getBearerToken(proto, host, port, clientId, clientSecret, grantType, scope) {
    const url = `${proto}://${host}:${port}/oauth2/token`;
    const credentials = `${clientId}:${clientSecret}`;
    const encodedCredentials = encoding.b64encode(credentials);
    const payload = `grant_type=${grantType}&scope=${scope}`;
    const params = {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${encodedCredentials}`,
        },
    };
    return http.post(url, payload, params);
}

export function setup() {
    const bearerToken = getBearerToken('http','auth-server', 9090, 'k6', 'k6-secret', 'client_credentials', 'local').json('access_token');
    return {
        token: bearerToken
    }
}

export default function (data) {
    const url = 'http://transaction-service:8080/transactions/random';

    const params = {
        headers: {
            'Authorization': `Bearer ${data.token}`,
        },
    };
    const res = http.post(url, {}, params);
    if (res.status !== 201){
        console.log(`Failed to create transaction: ${JSON.stringify(res)}`);
    }
    check(res, { "status is 201": (r) => r.status === 201 });
    sleep(1);
}