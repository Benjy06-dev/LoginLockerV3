import threading

# Create a join list @ Module Level
join_list = list()


# Class
class ThreadHandler:
    @staticmethod
    def run(func, enable_join):
        thread = threading.Thread(target=func)
        thread.start()
        if enable_join:
            join_list.append(thread)

    @staticmethod
    def run_daemon(func):
        daemon_thread = threading.Thread(target=func, daemon=True)
        daemon_thread.start()

    @staticmethod
    def join_all():
        for thread in join_list:
            thread.join()

    @staticmethod
    def join_index(index):
        join_list[index].join()

    @staticmethod
    def clear_join_flags():
        global join_list
        join_list = list()

    @staticmethod
    def list_joins():
        return join_list
