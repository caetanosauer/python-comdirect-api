import requests
import uuid
import base64
import json
import time
import threading

import comdirect_api.types
from comdirect_api.utils import default_callback_p_tan, \
    default_callback_m_tan,\
    default_callback_p_tan_push,\
    timestamp


class Session:
    def __init__(
        self,
        username,
        password,
        client_id,
        client_secret,
        callback_p_tan=default_callback_p_tan,
        callback_m_tan=default_callback_m_tan,
        callback_p_tan_push=default_callback_p_tan_push,
        autorefresh=False,
    ):
        self.autorefresh = autorefresh

        # POST /oauth/token
        response = requests.post(
            "https://api.comdirect.de/oauth/token",
            f"client_id={client_id}&"
            f"client_secret={client_secret}&"
            f"username={username}&"
            f"password={password}&"
            f"grant_type=password",
            allow_redirects=False,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if not response.status_code == 200:
            raise RuntimeError(
                f"POST https://api.comdirect.de/oauth/token returned status {response.status_code}"
            )
        tmp = response.json()
        self.access_token = tmp["access_token"]
        self.refresh_token = tmp["refresh_token"]

        # GET /session/clients/user/v1/sessions
        self.session_id = uuid.uuid4()
        response = requests.get(
            "https://api.comdirect.de/api/session/clients/user/v1/sessions",
            allow_redirects=False,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.access_token}",
                "x-http-request-info": f'{{"clientRequestId":{{"sessionId":"{self.session_id}",'
                f'"requestId":"{timestamp()}"}}}}',
            },
        )
        if not response.status_code == 200:
            raise RuntimeError(
                f"GET https://api.comdirect.de/api/session/clients/user/v1/sessions"
                f"returned status {response.status_code}"
            )
        tmp = response.json()
        self.session_id = tmp[0]["identifier"]

        # POST /session/clients/user/v1/sessions/{sessionId}/validate
        response = requests.post(
            f"https://api.comdirect.de/api/session/clients/user/v1/sessions/{self.session_id}/validate",
            allow_redirects=False,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.access_token}",
                "x-http-request-info": f'{{"clientRequestId":{{"sessionId":"{self.session_id}",'
                f'"requestId":"{timestamp()}"}}}}',
                "Content-Type": "application/json",
            },
            data=f'{{"identifier":"{self.session_id}","sessionTanActive":true,"activated2FA":true}}',
        )
        if response.status_code != 201:
            raise RuntimeError(
                f"POST /session/clients/user/v1/sessions/.../validate returned status code {response.status_code}"
            )
        tmp = json.loads(response.headers["x-once-authentication-info"])
        challenge_id = tmp["id"]
        typ = tmp["typ"]
        if typ == "P_TAN":
            challenge = tmp["challenge"]
            if callback_p_tan:
                tan = callback_p_tan(base64.b64decode(challenge))
            else:
                # TODO: we could retry with other TAN type...
                raise RuntimeError(
                    "cannot handle photo tan because you did not provide handler"
                )
        elif typ == "M_TAN":
            challenge = tmp["challenge"]
            if callback_m_tan:
                tan = callback_m_tan()
            else:
                # TODO: we could retry with other TAN type...
                raise RuntimeError(
                    "cannot handle SMS tan because you did not provide handler"
                )
        elif typ == "P_TAN_PUSH":
            # challenge is not available for push-tan,wait for confirmation
            if callback_p_tan_push:
                tan = callback_p_tan_push()
            else:
                # TODO: we could retry with other TAN type...
                raise RuntimeError(
                    "cannot handle SMS tan because you did not provide handler"
                )
        else:
            raise RuntimeError(f"unknown TAN type {typ}")

        # PATCH /session/clients/user/v1/sessions/{sessionId}
        response = requests.patch(
            f"https://api.comdirect.de/api/session/clients/user/v1/sessions/{self.session_id}",
            allow_redirects=False,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.access_token}",
                "x-http-request-info": f'{{"clientRequestId":{{"sessionId":"{self.session_id}",'
                f'"requestId":"{timestamp()}"}}}}',
                "Content-Type": "application/json",
                "x-once-authentication-info": f'{{"id":"{challenge_id}"}}',
                "x-once-authentication": tan,
            },
            data=f'{{"identifier":"{self.session_id}","sessionTanActive":true,"activated2FA":true}}',
        )
        tmp = response.json()
        if not response.status_code == 200:
            raise RuntimeError(
                f"PATCH https://api.comdirect.de/session/clients/user/v1/sessions/...:"
                f"returned status {response.status_code}"
            )
        self.session_id = tmp["identifier"]

        # POST https://api.comdirect.de/oauth/token
        response = requests.post(
            "https://api.comdirect.de/oauth/token",
            allow_redirects=False,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=f"client_id={client_id}&client_secret={client_secret}&"
                 f"grant_type=cd_secondary&token={self.access_token}",
        )
        if not response.status_code == 200:
            raise RuntimeError(
                f"POST https://api.comdirect.de/oauth/token returned status {response.status_code}"
            )
        tmp = response.json()
        self.access_token = tmp["access_token"]
        self.refresh_token = tmp["refresh_token"]
        self.kdnr = tmp["kdnr"]  # Kundennummer / number of customer
        self.bpid = tmp["bpid"]  # no clue what this is
        self.kontakt_id = tmp["kontaktId"]  # no clue what this is
        self.isRevoked = False

        if self.autorefresh:
            self.refreshThread = threading.Thread(target=self._refresh_worker)
            self.refreshThread.start()

    def _refresh_worker(self):
        while not self.isRevoked:
            time.sleep(9 * 60)
            if self.isRevoked:
                break
            else:
                self.refresh()

    def revoke(self):
        if not self.isRevoked:
            # DELETE https://api.comdirect.de/oauth/revoke
            response = requests.delete(
                "https://api.comdirect.de/oauth/revoke",
                allow_redirects=False,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data=f'{{"identifier":"{self.session_id}","sessionTanActive":true,"activated2FA":true}}',
            )
            if not response.status_code == 204:
                raise RuntimeError(
                    f"DELETE https://api.comdirect.de/oauth/revoke returned unexpected status {response.status_code}"
                )
            self.isRevoked = True

    def refresh(self):
        # https://api.comdirect.de/oauth/revoke
        response = requests.delete(
            "https://api.comdirect.de/oauth/revoke",
            allow_redirects=False,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=f'{{"identifier":"{self.session_id}","sessionTanActive":true,"activated2FA":true}}',
        )
        if not response.status_code == 204:
            raise RuntimeError(
                f"DELETE https://api.comdirect.de/oauth/revoke returned unexpected status {response.status_code}"
            )
        self.isRevoked = True

    def _get_authorized(self, url, extraheaders={}):
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.access_token}",
            "x-http-request-info": f'{{"clientRequestId":{{"sessionId":"{self.session_id}",'
            f'"requestId":"{timestamp()}"}}}}',
        }
        headers.update(extraheaders)
        response = requests.get(url, allow_redirects=False, headers=headers)
        if response.status_code != 200:
            raise RuntimeError(f"{url} returned HTTP status {response.status_code}")
        return response

    # ------------------------------ ACCOUNT ----------------------------------
    # GET /banking/clients/user/v1/accounts/balances
    def account_get_balances(self, paging_first=0, paging_count=1000):
        response = self._get_authorized(
            f"https://api.comdirect.de/api/banking/clients/user/v1/accounts/balances"
            f"?paging-first={paging_first}&paging-count={paging_count}")
        return [comdirect_api.types.AccountBalance(i) for i in response.json()["values"]]

    # GET /banking/v2/accounts/{accountid}/balances
    def account_get_balance(self, accountid):
        response = self._get_authorized(f"https://api.comdirect.de/api/banking/v2/accounts/{accountid}/balances")
        return comdirect_api.types.AccountBalance(response.json())

    # GET /banking/v2/accounts/{accountid}/transactions
    # TODO: The filters do not yet work.
    # see https://community.comdirect.de/t5/Website-Apps/Rest-API-Filter-Parameter/m-p/108710
    def account_get_transactions(self, accountid, transactionDirection="CREDIT_AND_DEBIT",
                                 min_bookingdate=None, max_bookingdate=None, transactionState="BOTH"):
        parameters = f"transactionDirection={transactionDirection}&transactionState={transactionState}"
        if min_bookingdate:
            parameters += f"&min-bookingdate={min_bookingdate}"
        if max_bookingdate:
            parameters += f"&min-bookingdate={max_bookingdate}"
        response = self._get_authorized(
            f"https://api.comdirect.de/api/banking/v1/accounts/{accountid}/transactions?{parameters}")
        return [comdirect_api.types.AccountTransaction(i) for i in response.json()["values"]]

    # ------------------------------ DOCUMENTS --------------------------------
    # GET /messages/clients/user/v2/documents
    def documents_list(self, uuid=None, paging_first=0, paging_count=1000):
        if uuid is None:
            uuid = "user"
        response = self._get_authorized(
            f"https://api.comdirect.de/api/messages/clients/{uuid}/v2/documents?"
            f"paging-first={paging_first}&paging-count={paging_count}")
        return [comdirect_api.types.Document(i) for i in response.json()["values"]]

    # GET /messages/v2/documents/{documentId}
    def documents_download(self, document):
        response = self._get_authorized(f"https://api.comdirect.de/api/messages/v2/documents/{document.documentId}",
                                        extraheaders={"Accept": document.mimeType})
        return response.content
