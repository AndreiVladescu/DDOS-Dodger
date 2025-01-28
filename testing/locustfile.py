from locust import HttpUser, task, between

class ESP8266User(HttpUser):
    wait_time = between(1, 5)

    @task
    def access_server(self):
        self.client.get("/")