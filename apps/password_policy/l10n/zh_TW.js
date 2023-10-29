OC.L10N.register(
    "password_policy",
    {
    "Password is expired, please use forgot password method to reset" : "密碼已到期，請使用忘記密碼方式重設",
    "Password must not have been used recently before." : "密碼不可以是近期使用過的。",
    "Password is among the 1,000,000 most common ones. Please make it unique." : "密碼出現在 1,000,000 個常用密碼列表內。請設定獨一無二的密碼。",
    "Password is present in compromised password list. Please choose a different password." : "密碼出現在洩露的密碼清單中。請選擇其它密碼。",
    "Password needs to be at least %s characters long." : "密碼需長於 %s 個字母。",
    "Password needs to contain at least one numeric character." : "密碼需要包含至少一個數字。",
    "Password needs to contain at least one special character." : "密碼應包含一個特殊符號。",
    "Password needs to contain at least one lower and one upper case character." : "密碼應包含最少一個大寫與一個小寫字母。",
    "Password policy" : "密碼策略",
    "Allows admins to configure a password policy" : "讓管理員可以設定密碼策略",
    "Allow admin to define certain pre-conditions for password, e.g. enforce a minimum length" : "允許管理員定義密碼的某些條件，例如強制最小長度",
    "Saved" : "已儲存",
    "Minimum password length" : "密碼最小長度",
    "User password history" : "使用者密碼歷史紀錄",
    "Number of days until user password expires" : "密碼到期天數",
    "Number of login attempts before the user account is blocked (0 for no limit)" : "封鎖使用者帳號前的登入嘗試次數（0 為不限制）",
    "Forbid common passwords" : "禁止常見的密碼",
    "Enforce upper and lower case characters" : "強制使用大寫與小寫字母",
    "Enforce numeric characters" : "強制使用數字字元",
    "Enforce special characters" : "強制使用特殊字元",
    "Check password against the list of breached passwords from haveibeenpwned.com" : "將密碼與來自 haveibeenpwned.com 的外洩密碼列表進行核對",
    "This check creates a hash of the password and sends the first 5 characters of this hash to the haveibeenpwned.com API to retrieve a list of all hashes that start with those. Then it checks on the Nextcloud instance if the password hash is in the result set." : "此項檢查會建立密碼的雜湊值，並傳送此雜湊值的前五個字元到 haveibeenpwned.com 的 API 來擷取以這些字元開頭的所有雜湊值列表。然後如果密碼雜湊值包含在結果集中，其將在 Nextcloud 站台上檢查。",
    "Unknown error" : "未知錯誤",
    "Minimal length has to be a non negative number" : "最小長度必須為非負數",
    "History size has to be a non negative number" : "歷史紀錄大小必須為非負數",
    "Expiration days have to be a non negative number" : "到期天數必須為非負數",
    "Maximum login attempts have to be a non negative number" : "最大登入嘗試次數必須為非負數",
    "Error while saving" : "儲存時發生錯誤"
},
"nplurals=1; plural=0;");
