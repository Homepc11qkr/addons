import paho.mqtt.client as mqtt
import re
from json import dumps as json_dumps
from functools import reduce
from collections import defaultdict
import time

MQTT_USERNAME = 'SHOULD_BE_CHANGED'
MQTT_PASSWORD = 'SHOULD_BE_CHANGED'
MQTT_SERVER = '192.168.0.35'
ROOT_TOPIC_NAME = 'rs485_2mqtt'
HOMEASSISTANT_ROOT_TOPIC_NAME = 'homeassistant'


class Wallpad:
    _device_list = []

    def __init__(self):
        self.mqtt_client = mqtt.Client(protocol=mqtt.MQTTv311, callback_api_version=2)  # 최신 API 버전 사용
        self.mqtt_client.on_message = self.on_raw_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)

        self.connect_mqtt()

    def connect_mqtt(self):
        """MQTT 연결을 시도하고 실패 시 재시도"""
        while True:
            try:
                print("MQTT 브로커 연결 시도 중...")
                self.mqtt_client.connect(MQTT_SERVER, 1883)
                self.mqtt_client.loop_start()  # 별도 스레드에서 실행
                print("MQTT 연결 성공")
                break
            except Exception as e:
                print(f"MQTT 연결 실패: {e}, 5초 후 재시도")
                time.sleep(5)

    def on_connect(self, client, userdata, flags, rc):
        """연결 성공 시 호출"""
        if rc == 0:
            print("MQTT 브로커 연결 성공")
            self.register_mqtt_discovery()  # 연결 성공 후 Home Assistant에 장치 등록
        else:
            print(f"MQTT 연결 실패, 코드: {rc}")

    def on_disconnect(self, client, userdata, rc):
        """연결이 끊어졌을 때 자동으로 재연결"""
        print(f"MQTT 연결 해제됨. rc: {rc}")
        self.connect_mqtt()  # 연결 재시도

    def register_mqtt_discovery(self):
        """Home Assistant에 MQTT 장치 자동 등록"""
        for device in self._device_list:
            if device.mqtt_discovery:
                topic = '/'.join([HOMEASSISTANT_ROOT_TOPIC_NAME, device.device_class, device.device_unique_id, 'config'])
                payload = device.get_mqtt_discovery_payload()
                
                if self.mqtt_client.is_connected():  # 연결 확인 후 publish 실행
                    self.mqtt_client.publish(topic, payload, qos=2, retain=True)
                else:
                    print(f"MQTT 연결 끊김, {topic} 전송 실패")

    def listen(self):
        """MQTT 메시지 수신을 위한 루프 실행"""
        topics = [ROOT_TOPIC_NAME + '/dev/raw'] + self.get_topic_list_to_listen()
        self.mqtt_client.subscribe([(topic, 2) for topic in topics])
        print("MQTT 구독 시작")
        self.mqtt_client.loop_forever()

    def on_raw_message(self, client, userdata, msg):
        """MQTT 메시지 수신 시 호출"""
        print(f"수신된 메시지: {msg.topic} - {msg.payload}")

    def add_device(self, device_name, device_id, device_subid, device_class, child_device=[], mqtt_discovery=True, optional_info={}):
        device = Device(device_name, device_id, device_subid, device_class, child_device, mqtt_discovery, optional_info)
        self._device_list.append(device)
        return device

    def get_topic_list_to_listen(self):
        topics = []
        for device in self._device_list:
            for attr in device.get_status_attr_list():
                topics.append('/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, attr, 'set']))
        return topics


class Device:
    def __init__(self, device_name, device_id, device_subid, device_class, child_device, mqtt_discovery, optional_info):
        self.device_name = device_name
        self.device_id = device_id
        self.device_subid = device_subid
        self.device_unique_id = 'rs485_' + self.device_id + '_' + self.device_subid
        self.device_class = device_class
        self.child_device = child_device
        self.mqtt_discovery = mqtt_discovery
        self.optional_info = optional_info
        self.__status_messages_map = defaultdict(list)
        self.__command_messages_map = {}

    def register_status(self, message_flag, attr_name, regex, topic_class, process_func=lambda v: v):
        self.__status_messages_map[message_flag].append({
            'regex': regex,
            'process_func': process_func,
            'device_name': self.device_name,
            'attr_name': attr_name,
            'topic_class': topic_class
        })

    def register_command(self, message_flag, attr_name, topic_class, process_func=lambda v: v):
        self.__command_messages_map[attr_name] = {
            'message_flag': message_flag,
            'attr_name': attr_name,
            'topic_class': topic_class,
            'process_func': process_func
        }

    def get_status_attr_list(self):
        return list({status['attr_name'] for status_list in self.__status_messages_map.values() for status in status_list})

    def get_mqtt_discovery_payload(self):
        result = {
            '~': '/'.join([ROOT_TOPIC_NAME, self.device_class, self.device_name]),
            'name': self.device_name,
            'uniq_id': self.device_unique_id,
        }
        result.update(self.optional_info)
        for status_list in self.__status_messages_map.values():
            for status in status_list:
                result[status['topic_class']] = '/'.join(['~', status['attr_name']])
        for cmd in self.__command_messages_map.values():
            result[cmd['topic_class']] = '/'.join(['~', cmd['attr_name'], 'set'])
        result['device'] = {
            'identifiers': self.device_unique_id,
            'name': self.device_name
        }
        return json_dumps(result, ensure_ascii=False)


# =============================
# 장치 등록 예제
# =============================
wallpad = Wallpad()

# 조명
optional_info_light = {'optimistic': 'false'}
거실1전등 = wallpad.add_device(device_name='거실1전등', device_id='19', device_subid='11', device_class='light', optional_info=optional_info_light)

# 조명 상태 등록
light_regex = r'^(?P<cmd>[0-9a-f]{2})(?P<val>[0-9a-f]{2})'
거실1전등.register_status(message_flag='04', attr_name='power', topic_class='state_topic',
                          regex=light_regex,
                          process_func=lambda gd: 'ON' if gd['cmd'] == '01' and gd['val'] == '01' else 'OFF')
거실1전등.register_command(message_flag='02', attr_name='power', topic_class='command_topic',
                          process_func=lambda v: '01' if v.upper() == 'ON' else '02')

# =============================
# 프로그램 시작
# =============================
wallpad.listen()
# 2025_0202_2105_08
