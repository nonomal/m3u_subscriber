import uuid
from datetime import datetime


def generate_only_uuid(my_string):
   now = datetime.now()
   timestamp = now.strftime("%Y%m%d%H%M%S%f")
   unique_str = f"{timestamp}-{my_string}"
   serial_number = uuid.uuid5(uuid.NAMESPACE_URL, unique_str)
   return serial_number

if __name__ == '__main__':
    print(generate_only_uuid("混合了各种符号、中文、英文和数字！@#￥%……&*（）——+{}：“《》？abc123"))
