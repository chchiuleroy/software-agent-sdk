# 帳號申請與部門（P1）— 設計 v1

狀態：2026-10-08 Roy 核可 Gate 1（方向 A，先做 P1）與 Gate 2（模組與介面）。實作中。
範圍：只有 central-governance-api。P2（部門工具權限）、P3（模型閘道）另案。

## 1. 已決定（Roy，2026-10-08）

- `superadmin` 是比 `governance.admin` 更高的角色，管：批准帳號建立、部門與部門角色權限設定、AI 模型連線。
- 任何人可自行申請帳號；申請人此時沒有帳號；表單含 EMAIL，superadmin 審核（EMAIL 非公司網域即拒絕）。
- 部門由 central 自建表管理（不依賴 Keycloak group／claim）。
- 批准後由 superadmin 手動去 Keycloak 建帳號；central 不持有建帳號憑證。
- 首次登入以 EMAIL 對應已批准的申請。
- 預設（Roy 未明確回覆，小c 先採用）：A2 `governance.superadmin` 為 Keycloak realm role，由 Keycloak 管理員授予，OHS 內不能自授；A3 公開申請端點預設關閉，`CGA_ACCOUNT_REQUESTS_ENABLED=true` 才開。

## 2. 範圍外

按路徑範圍的權限、部門限制既有核准端點（P2）、模型閘道（P3）、稽核簽章鏈、Keycloak Admin API 自動建帳號、裝置清冊 UI。

## 3. 模組與介面

身分：`Principal` 新增 `email`、`email_verified`；`KNOWN_ROLES` 加入 `governance.superadmin`，它不自動等同 `governance.admin`。

資料表（新 migration，`down_revision = a3c5e91b7d20`）：

- `departments`：`id`、`name`（唯一）、`disabled_at`
- `account_requests`：`id`、`email`（小寫）、`display_name`、`requested_department`（自由文字）、`reason`、`status`（`pending_verification`／`pending_review`／`approved`／`rejected`／`expired`）、`code_hmac`、`code_expires_at`、`code_attempts`、`email_verified_at`、`decided_by_issuer/sub`、`decided_at`、`decision_reason`、`approved_department_id`
- `account_memberships`：`id`、`email`（唯一）、`department_id`、`account_request_id`、`bound_issuer`、`bound_sub`、`bound_at`

端點：

- 公開（受 `account_requests_enabled` 控制，關閉時 404）：`POST /account-requests`、`POST /account-requests/{id}/verify`
- superadmin：`GET/POST /admin/departments`、`POST /admin/departments/{id}/disable`、`GET /admin/account-requests`、`POST /admin/account-requests/{id}/approve`、`POST /admin/account-requests/{id}/reject`、`GET /admin/memberships?unbound=true`
- 已登入：`GET /me`（首次登入綁定）

驗證用 8 位驗證碼（不用連結，避免信箱安全掃描預先點開）；HMAC-SHA256 加伺服器金鑰存放；有效 15 分鐘；最多試 5 次。寄信用標準函式庫 `smtplib`，SMTP 未設定時建立端點回 503（fail closed）。

## 4. 失敗模式

- 首次綁定只綁一次：條件式 UPDATE（`WHERE bound_sub IS NULL`）；要求 token 的 `email_verified=true`；綁定後以 `(issuer, sub)` 為準，EMAIL 不再重新授權。
- 公開的建立／驗證沒有登入者，`AdminAuditEvent` 的 actor 欄位必填，所以只有 superadmin 的動作寫稽核事件。
- superadmin 不能批准 EMAIL 等於自己的申請。
- 網域白名單為空 = 全拒。速率限制用資料表計數（多 worker 下行程內計數會失效）；數字為判斷值，非量測值。
- 已知限度：P1 不拿部門限制既有核准端點；速率限制不含 IP（反向代理後的來源 IP 未設計）。

## 5. 實作順序

1. Principal／KNOWN_ROLES　2. models＋migration　3. config＋mailer　4. 公開端點　5. superadmin 端點　6. `/me` 首次綁定　7. 端到端（真 Keycloak 的 role／mapper 須 Roy 以管理員建立）　8. 小o 審查、ruff、pyright、draft PR。

## 6. 實作時偏離設計之處（Deviations）

- **驗證端點改為 `POST /account-requests/verify`，body 為 `{email, code}`**，不再用路徑上的 request id。原因：不必向未登入者回傳 id；有 id 的話，知道某個 EMAIL 的第三者可以替它耗盡 5 次嘗試。
- **每次送出都新建一筆申請**，同 EMAIL 較舊的未驗證申請改為 `expired`；以 partial unique index（同一 EMAIL 最多一筆 `pending_verification` 或 `pending_review`）保證併發安全。因此「每 EMAIL 每日上限」直接數資料列。
- **寄信失敗時刪除該列**並回 503，避免我們的 SMTP 故障耗掉申請人的每日額度。
- **superadmin 的決定動作不使用 Idempotency-Key**，改靠條件式狀態轉換；重送得 409 `account_request_not_pending`。
- **未涵蓋**：第三者可用已知 EMAIL 耗盡該 EMAIL 的每日 3 次額度（造成暫時性拒絕服務）；速率限制不含來源 IP；對 `email_verified` 的信任取決於 Keycloak realm 設定（是否允許使用者自改 EMAIL、是否要求驗證）——尚未核實。
