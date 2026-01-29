# BFLA COCO Annotator in DELETE /api/undo/

| Project | Version | CNA |
| --- | --- | --- |
| Coco Annotator | **`v0.11.1`** | VulDB |

**📝 Summary**

An attacker can delete categories created by other users via a DELETE request to the /api/undo/ endpoint without any ownership or permission checks. This constitutes a **Broken Function Level Authorization (BFLA)** vulnerability, allowing unauthorized manipulation of protected resources.

---

**🔎 Details**

➤ Vulnerable Endpoint: `/api/undo/`

➤ Parameter: `?id=`

---

**📚 PoC**

**1. Create a new category with a user with admin privileges:**

![image.png](image.png)

**2. Then, another user sent a request to delete the category; in this case, the admin created the category with ID 200.**

Request to view ID 200 category failed because users can only see their own category.

![image.png](image%201.png)

Please delete the newly created category with ID 200.

![image.png](image%202.png)

The application accepts the request without validating that the user has permission to delete this category.

1. An attacker can exploit this vulnerability to delete all categories within the application.
    1. Checking categories before the attack:
    
    ![image.png](image%203.png)
    

Executing the attack to delete category IDs ranging from 1 to 200.

![image.png](image%204.png)

Checking the results returned a Status 200 with a success message. A normal user was able to delete all categories in the application for all users.

![image.png](image%205.png)

Confirm with the admin user that the application currently has no categories after the attack.

![image.png](image%206.png)

---

**⚠️ Impact**

- Any authenticated user can delete categories created by other users.
- No verification is done to ensure that the requester is the original creator or has elevated permissions (e.g., admin).
- Leads to **data integrity issues**, potential **denial of service**, or abuse in **multi-tenant environments**.

---

**🔗 References**

- [OWASP API Security Top 10 – BFLA](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- CWE-285: Improper Authorization

---

**🕵🏻‍♀️ Finder**

*Discovered by Thoropass Researcher Natan Morette*