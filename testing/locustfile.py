from locust import HttpUser, task, between

# locust -f locustfile.py --host=http://192.168.0.90

class ESP8266User(HttpUser):
    wait_time = between(1, 5)

    @task
    def access_server(self):
        self.client.get("/")
