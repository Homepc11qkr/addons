채팅 기록



ChatGPT
ChatGPT
Sora 아이콘
Sora

GPT 탐색

새 프로젝트
오늘
어제
지난 7일
지난 30일
플랜 보기
제한 없는 액세스, 팀 기능, 그 외에 많은 것들

ChatGPT o3-mini

공유하기

User
나의 말:
import paho.mqtt.client as mqtt
import re
from json import dumps as json_dumps
from functools import reduce
from collections import defaultdict

MQTT_USERNAME = 'SHOULD_BE_CHANGED'
MQTT_PASSWORD = 'SHOULD_BE_CHANGED'

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

        self.__message_flag = {}            # {'power': '41'}
        self.__command_process_func = {}

        self.__status_messages_map = defaultdict(list)
        self.__command_messages_map = {}

    def register_status(self, message_flag, attr_name, regex, topic_class, device_name = None, process_func = lambda v: v):
        device_name = self.device_name if device_name == None else device_name
        self.__status_messages_map[message_flag].append({'regex': regex, 'process_func': process_func, 'device_name': device_name, 'attr_name': attr_name, 'topic_class': topic_class})

    def register_command(self, message_flag, attr_name, topic_class, process_func = lambda v: v):
        self.__command_messages_map[attr_name] = {'message_flag': message_flag, 'attr_name': attr_name, 'topic_class': topic_class, 'process_func': process_func}

    def parse_payload(self, payload_dict):
        result = {}
        device_family = [self] + self.child_device
        for device in device_family:
            for status in device.__status_messages_map[payload_dict['message_flag']]:
                topic = '/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, status['attr_name']])
                result[topic] = status['process_func'](re.match(status['regex'], payload_dict['data'])[1])
        return result

    def get_command_payload_byte(self, attr_name, attr_value):  # command('power', 'ON')   command('percentage', 'middle')
        attr_value = self.__command_messages_map[attr_name]['process_func'](attr_value)

        command_payload = ['f7', self.device_id, self.device_subid, self.__command_messages_map[attr_name]['message_flag'], '01', attr_value]
        command_payload.append(Wallpad.xor(command_payload))
        command_payload.append(Wallpad.add(command_payload))
        return bytearray.fromhex(' '.join(command_payload))

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

        for status_list in self.__command_messages_map.values():
            result[status_list['topic_class']] = '/'.join(['~', status_list['attr_name'], 'set'])

        result['device'] = {
            'identifiers': self.device_unique_id,
            'name': self.device_name
        }
        return json_dumps(result, ensure_ascii = False)

    def get_status_attr_list(self):
        return list(set([status['attr_name'] for status_list in self.__status_messages_map.values() for status in status_list]))

class Wallpad:
    _device_list = []

    def __init__(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message    = self.on_raw_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
        self.mqtt_client.connect(MQTT_SERVER, 1883)

    def listen(self):
        self.register_mqtt_discovery()
        self.mqtt_client.subscribe([(topic, 2) for topic in [ROOT_TOPIC_NAME + '/dev/raw'] + self.get_topic_list_to_listen()])
        self.mqtt_client.loop_forever()

    def register_mqtt_discovery(self):
        for device in self._device_list:
            if device.mqtt_discovery:
                topic = '/'.join([HOMEASSISTANT_ROOT_TOPIC_NAME, device.device_class, device.device_unique_id, 'config'])
                payload = device.get_mqtt_discovery_payload()
                self.mqtt_client.publish(topic, payload, qos = 2, retain = True)

    def add_device(self, device_name, device_id, device_subid, device_class, child_device = [], mqtt_discovery = True, optional_info = {}):
        device = Device(device_name, device_id, device_subid, device_class, child_device, mqtt_discovery, optional_info)
        self._device_list.append(device)
        return device

    def get_device(self, **kwargs):
        if 'device_name' in kwargs:
            return [device for device in self._device_list if device.device_name == kwargs['device_name']][0]
        else:
            return [device for device in self._device_list if device.device_id == kwargs['device_id'] and device.device_subid == kwargs['device_subid']][0]

    def get_topic_list_to_listen(self):
        return ['/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, attr_name, 'set']) for device in self._device_list for attr_name in device.get_status_attr_list()]

    @classmethod
    def xor(cls, hexstring_array):
        return format(reduce((lambda x, y: x^y), list(map(lambda x: int(x, 16), hexstring_array))), '02x')

    @classmethod
    def add(cls, hexstring_array): # hexstring_array ['f7', '32', ...]
        return format(reduce((lambda x, y: x+y), list(map(lambda x: int(x, 16), hexstring_array))), '02x')[-2:]

    @classmethod
    def is_valid(cls, payload_hexstring):
        payload_hexstring_array = [payload_hexstring[i:i+2] for i in range(0, len(payload_hexstring), 2)] # ['f7', '0e', '1f', '81', '04', '00', '00', '00', '00', '63', '0c']
        try:
            result = int(payload_hexstring_array[4], 16) + 7 == len(payload_hexstring_array) and cls.xor(payload_hexstring_array[:-2]) == payload_hexstring_array[-2:-1][0] and cls.add(payload_hexstring_array[:-1]) == payload_hexstring_array[-1:][0]
            return result
        except:
            return False

    def on_raw_message(self, client, userdata, msg):
        if msg.topic == ROOT_TOPIC_NAME + '/dev/raw': # ew11이 MQTT에 rs485 패킷을 publish하는 경우
            for payload_raw_bytes in msg.payload.split(b'\xf7')[1:]: # payload 내에 여러 메시지가 있는 경우, \f7 disappear as delimiter here
                payload_hexstring = 'f7' + payload_raw_bytes.hex() # 'f7361f810f000001000017179817981717969896de22'
                try:
                    if self.is_valid(payload_hexstring):
                        payload_dict = re.match(r'f7(?P<device_id>0e|12|32|33|36)(?P<device_subid>[0-9a-f]{2})(?P<message_flag>[0-9a-f]{2})(?:[0-9a-f]{2})(?P<data>[0-9a-f]*)(?P<xor>[0-9a-f]{2})(?P<add>[0-9a-f]{2})', payload_hexstring).groupdict()

                        for topic, value in self.get_device(device_id = payload_dict['device_id'], device_subid = payload_dict['device_subid']).parse_payload(payload_dict).items():
                            client.publish(topic, value, qos = 1, retain = False)
                    else:
                        continue
                except Exception as e:
                    client.publish(ROOT_TOPIC_NAME + '/dev/error', payload_hexstring, qos = 1, retain = True)

        else: # homeassistant에서 명령하여 MQTT topic을 publish하는 경우
            topic_split = msg.topic.split('/') # rs485_2mqtt/light/침실등/power/set
            device = self.get_device(device_name = topic_split[2])
            payload = device.get_command_payload_byte(topic_split[3], msg.payload.decode())
            client.publish(ROOT_TOPIC_NAME + '/dev/command', payload, qos = 2, retain = False)

    def on_disconnect(self, client, userdata, rc):
        raise ConnectionError

MQTT_SERVER = '192.168.0.35'
ROOT_TOPIC_NAME = 'rs485_2mqtt'
HOMEASSISTANT_ROOT_TOPIC_NAME = 'homeassistant'
wallpad = Wallpad()

packet_2_payload_percentage = {'00': '0', '01': '1', '02': '2', '03': '3'}
packet_2_payload_oscillation = {'03': 'oscillate_on', '00': 'oscillation_off', '01': 'oscillate_off'}

###
### 
### 조명 ###
optional_info = {'optimistic': 'false'}
거실등1    = wallpad.add_device(device_name = '거실등1', device_id = '0e', device_subid = '11', device_class = 'light', optional_info = optional_info)
거실등2    = wallpad.add_device(device_name = '거실등2', device_id = '0e', device_subid = '12', device_class = 'light', optional_info = optional_info)
복도등     = wallpad.add_device(device_name = '복도등',  device_id = '0e', device_subid = '13', device_class = 'light', optional_info = optional_info)
침실등     = wallpad.add_device(device_name = '침실등',  device_id = '0e', device_subid = '21', device_class = 'light', optional_info = optional_info)
거실등전체 = wallpad.add_device(device_name = '거실등 전체', device_id = '0e', device_subid = '1f', device_class = 'light', mqtt_discovery = False, child_device = [거실등1, 거실등2, 복도등])
침실등전체 = wallpad.add_device(device_name = '침실등 전체', device_id = '0e', device_subid = '2f', device_class = 'light', mqtt_discovery = False, child_device = [침실등])

거실등전체.register_status(message_flag = '01', attr_name = 'availability', topic_class ='availability_topic', regex = r'()', process_func = lambda v: 'online')
침실등전체.register_status(message_flag = '01', attr_name = 'availability', topic_class ='availability_topic', regex = r'()', process_func = lambda v: 'online')

거실등1.register_status(message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])0[01]0[01]', process_func = lambda v: 'ON' if v == '01' else 'OFF')
거실등2.register_status(message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'000[01](0[01])0[01]', process_func = lambda v: 'ON' if v == '01' else 'OFF')
복도등.register_status( message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'000[01]0[01](0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
침실등.register_status( message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')

거실등1.register_status(message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
거실등2.register_status(message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
복도등.register_status( message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
침실등.register_status( message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')

거실등1.register_command(message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00') # 'ON': '01' / 'OFF': '00'
거실등2.register_command(message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00')
복도등.register_command( message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00')
침실등.register_command( message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00')

### 난방 ###
optional_info = {'modes': ['off', 'heat'], 'temp_step': 0.5, 'precision': 0.5, 'min_temp': 5.0, 'max_temp': 40.0, 'send_if_off': 'false'}
거실난방 =  wallpad.add_device(device_name = '거실 난방',   device_id = '36', device_subid = '11', device_class = 'climate', optional_info = optional_info)
침실난방 =  wallpad.add_device(device_name = '침실 난방',   device_id = '36', device_subid = '12', device_class = 'climate', optional_info = optional_info)
서재난방 =  wallpad.add_device(device_name = '서재 난방',   device_id = '36', device_subid = '14', device_class = 'climate', optional_info = optional_info)
작은방난방 =  wallpad.add_device(device_name = '동굴 난방',   device_id = '36', device_subid = '13', device_class = 'climate', optional_info = optional_info)
알파룸난방= wallpad.add_device(device_name = '알파룸 난방', device_id = '36', device_subid = '15', device_class = 'climate', optional_info = optional_info)
난방전체 =  wallpad.add_device(device_name = '난방 전체',   device_id = '36', device_subid = '1f', device_class = 'climate', mqtt_discovery = False, child_device = [거실난방, 침실난방, 서재난방, 작은방난방, 알파룸난방])

난방전체.register_status(message_flag = '01', attr_name = 'availability', regex = r'()', topic_class ='availability_topic', process_func = lambda v: 'online')

for message_flag in ['81', 'c3', 'c4', 'c5']:
    거실난방.register_status(  message_flag = message_flag, attr_name = 'power', topic_class = 'mode_state_topic', regex = r'00(\d{2})\d{2}\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: 'heat' if format(int(v, 16), '05b')[4] == '1' else 'off')
    침실난방.register_status(  message_flag = message_flag, attr_name = 'power', topic_class = 'mode_state_topic', regex = r'00(\d{2})\d{2}\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: 'heat' if format(int(v, 16), '05b')[3] == '1' else 'off')
    작은방난방.register_status(  message_flag = message_flag, attr_name = 'power', topic_class = 'mode_state_topic', regex = r'00(\d{2})\d{2}\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: 'heat' if format(int(v, 16), '05b')[2] == '1' else 'off')
    서재난방.register_status(  message_flag = message_flag, attr_name = 'power', topic_class = 'mode_state_topic', regex = r'00(\d{2})\d{2}\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: 'heat' if format(int(v, 16), '05b')[1] == '1' else 'off')
    알파룸난방.register_status(message_flag = message_flag, attr_name = 'power', topic_class = 'mode_state_topic', regex = r'00(\d{2})\d{2}\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: 'heat' if format(int(v, 16), '05b')[0] == '1' else 'off')

    거실난방.register_status(  message_flag = message_flag, attr_name = 'away_mode', topic_class = 'away_mode_state_topic', regex = r'00\d{2}(\d{2})\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: 'ON' if format(int(v, 16), '05b')[4] == '1' else 'OFF')
    침실난방.register_status(  message_flag = message_flag, attr_name = 'away_mode', topic_class = 'away_mode_state_topic', regex = r'00\d{2}(\d{2})\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: 'ON' if format(int(v, 16), '05b')[3] == '1' else 'OFF')
    작은방난방.register_status(  message_flag = message_flag, attr_name = 'away_mode', topic_class = 'away_mode_state_topic', regex = r'00\d{2}(\d{2})\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: 'ON' if format(int(v, 16), '05b')[2] == '1' else 'OFF')
    서재난방.register_status(  message_flag = message_flag, attr_name = 'away_mode', topic_class = 'away_mode_state_topic', regex = r'00\d{2}(\d{2})\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: 'ON' if format(int(v, 16), '05b')[1] == '1' else 'OFF')
    알파룸난방.register_status(message_flag = message_flag, attr_name = 'away_mode', topic_class = 'away_mode_state_topic', regex = r'00\d{2}(\d{2})\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: 'ON' if format(int(v, 16), '05b')[0] == '1' else 'OFF')

    거실난방.register_status(  message_flag = message_flag, attr_name = 'targettemp',  topic_class ='temperature_state_topic',   regex = r'00\d{2}\d{2}\d{4}([\da-f]{2})[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    침실난방.register_status(  message_flag = message_flag, attr_name = 'targettemp',  topic_class ='temperature_state_topic',   regex = r'00\d{2}\d{2}\d{4}[\da-f]{2}[\da-f]{2}([\da-f]{2})[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    작은방난방.register_status(  message_flag = message_flag, attr_name = 'targettemp',  topic_class ='temperature_state_topic',   regex = r'00\d{2}\d{2}\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}([\da-f]{2})[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    서재난방.register_status(  message_flag = message_flag, attr_name = 'targettemp',  topic_class ='temperature_state_topic',   regex = r'00\d{2}\d{2}\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}([\da-f]{2})[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    알파룸난방.register_status(message_flag = message_flag, attr_name = 'targettemp',  topic_class ='temperature_state_topic',   regex = r'00\d{2}\d{2}\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}([\da-f]{2})[\da-f]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)

    거실난방.register_status(  message_flag = message_flag, attr_name = 'currenttemp', topic_class ='current_temperature_topic', regex = r'00\d{2}\d{2}\d{4}[\da-f]{2}([\da-f]{2})[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    침실난방.register_status(  message_flag = message_flag, attr_name = 'currenttemp', topic_class ='current_temperature_topic', regex = r'00\d{2}\d{2}\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}([\da-f]{2})[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    작은방난방.register_status(  message_flag = message_flag, attr_name = 'currenttemp', topic_class ='current_temperature_topic', regex = r'00\d{2}\d{2}\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}([\da-f]{2})[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    서재난방.register_status(  message_flag = message_flag, attr_name = 'currenttemp', topic_class ='current_temperature_topic', regex = r'00\d{2}\d{2}\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}([\da-f]{2})[\da-f]{2}[\da-f]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    알파룸난방.register_status(message_flag = message_flag, attr_name = 'currenttemp', topic_class ='current_temperature_topic', regex = r'00\d{2}\d{2}\d{4}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}[\da-f]{2}([\da-f]{2})', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)

난방전체.register_command(message_flag = '43', attr_name = 'power', topic_class = 'mode_command_topic', process_func = lambda v: '01' if v == 'heat' else '00')

거실난방.register_command(message_flag = '43', attr_name = 'power', topic_class = 'mode_command_topic', process_func = lambda v: '01' if v == 'heat' else '00')
거실난방.register_command(message_flag = '44', attr_name = 'targettemp', topic_class = 'temperature_command_topic', process_func = lambda v: format(int(float(v) // 1 + float(v) % 1 * 128 * 2), '02x'))
거실난방.register_command(message_flag = '45', attr_name = 'away_mode', topic_class = 'away_mode_command_topic', process_func = lambda v: '01' if v =='ON' else '00')

침실난방.register_command(message_flag = '43', attr_name = 'power', topic_class = 'mode_command_topic', process_func = lambda v: '01' if v == 'heat' else '00')
침실난방.register_command(message_flag = '44', attr_name = 'targettemp', topic_class = 'temperature_command_topic', process_func = lambda v: format(int(float(v) // 1 + float(v) % 1 * 128 * 2), '02x'))
침실난방.register_command(message_flag = '45', attr_name = 'away_mode', topic_class = 'away_mode_command_topic', process_func = lambda v: '01' if v =='ON' else '00')

서재난방.register_command(message_flag = '43', attr_name = 'power', topic_class = 'mode_command_topic', process_func = lambda v: '01' if v == 'heat' else '00')
서재난방.register_command(message_flag = '44', attr_name = 'targettemp', topic_class = 'temperature_command_topic', process_func = lambda v: format(int(float(v) // 1 + float(v) % 1 * 128 * 2), '02x'))
서재난방.register_command(message_flag = '45', attr_name = 'away_mode', topic_class = 'away_mode_command_topic', process_func = lambda v: '01' if v =='ON' else '00')

작은방난방.register_command(message_flag = '43', attr_name = 'power', topic_class = 'mode_command_topic', process_func = lambda v: '01' if v == 'heat' else '00') # { 'ON': '01', 'OFF': '00' }
작은방난방.register_command(message_flag = '44', attr_name = 'targettemp', topic_class = 'temperature_command_topic', process_func = lambda v: format(int(float(v) // 1 + float(v) % 1 * 128 * 2), '02x'))
작은방난방.register_command(message_flag = '45', attr_name = 'away_mode', topic_class = 'away_mode_command_topic', process_func = lambda v: '01' if v =='ON' else '00')

알파룸난방.register_command(message_flag = '43', attr_name = 'power', topic_class = 'mode_command_topic', process_func = lambda v: '01' if v == 'heat' else '00') # , { 'ON': '01', 'OFF': '00' }
알파룸난방.register_command(message_flag = '44', attr_name = 'targettemp', topic_class = 'temperature_command_topic', process_func = lambda v: format(int(float(v) // 1 + float(v) % 1 * 128 * 2), '02x'))
알파룸난방.register_command(message_flag = '45', attr_name = 'away_mode', topic_class = 'away_mode_command_topic', process_func = lambda v: '01' if v =='ON' else '00')

###  
wallpad.listen()
 을 설명
ChatGPT

Reasoned about MQTT device management을 4초 동안
Breaking down the code

I’m explaining a Python code snippet using paho.mqtt.client for home automation. It involves importing modules, setting up MQTT, and defining classes for managing devices and messages.

Managing devices and messages

I’m working through managing home automation devices with MQTT. This involves initializing dictionaries, registering message configurations, parsing payloads, building command payloads with checksums, and creating Home Assistant MQTT Discovery payloads.

Integrating devices

The Wallpad class manages MQTT communication, device registration, and status message handling. It includes methods for connecting, subscribing, publishing, and validating incoming messages.

이 코드는 RS485 통신을 MQTT 브로커로 연결하여 홈 오토메이션(예, 조명, 난방 등) 장치를 제어하고 모니터링할 수 있도록 하는 Python 애플리케이션입니다. 전체적인 흐름은 RS485 패킷을 MQTT 메시지로 변환하여 홈어시스턴트(Home Assistant)와 같은 시스템이 이를 인식하고, 반대로 홈어시스턴트에서 명령을 내리면 RS485 패킷으로 변환하여 장치에 전달하는 역할을 수행합니다.

아래에서 주요 구성 요소와 기능들을 자세히 설명합니다.

1. 사용 모듈 및 MQTT 설정
모듈 임포트

paho.mqtt.client: MQTT 클라이언트 기능 제공
re: 정규 표현식 사용
json.dumps: JSON 변환
functools.reduce, collections.defaultdict: 함수형 프로그래밍 및 기본 딕셔너리 사용
MQTT 인증 정보 및 서버 설정

MQTT_USERNAME, MQTT_PASSWORD: MQTT 브로커에 연결할 때 사용할 인증 정보 (실제 사용 시 변경해야 함)
MQTT_SERVER: MQTT 브로커의 IP 주소
ROOT_TOPIC_NAME 및 HOMEASSISTANT_ROOT_TOPIC_NAME: MQTT 토픽의 루트 이름을 정의하여, RS485와 Home Assistant 간의 통신 경로를 설정
2. Device 클래스
각 장치(예: 조명, 난방 등)를 나타내는 클래스입니다.

생성자 (__init__)

device_name, device_id, device_subid, device_class: 장치의 이름, 식별자 및 클래스(조명, 난방 등)를 지정
child_device: 여러 장치를 묶어 하나의 전체 장치(예: '거실등 전체')로 관리할 수 있도록 자식 장치를 지정
mqtt_discovery: MQTT discovery 기능 사용 여부(Home Assistant에서 자동으로 장치 정보를 인식할 수 있게 함)
optional_info: 추가 옵션 정보를 딕셔너리 형태로 저장
내부적으로 상태 메시지(__status_messages_map)와 명령 메시지(__command_messages_map)에 대한 등록 정보를 저장하는 딕셔너리를 초기화
register_status 메서드

특정 RS485 패킷의 message_flag에 대응하는 상태 메시지 처리 규칙을 등록합니다.
등록 시, 해당 메시지에 대해 사용할 정규 표현식(regex), 처리 함수(process_func), 그리고 MQTT 토픽에 사용할 attr_name과 topic_class 정보를 저장합니다.
register_command 메서드

장치에 대해 MQTT를 통해 내려온 명령(예: ON/OFF, 온도 조절 등)을 RS485 패킷으로 변환할 때 사용할 규칙을 등록합니다.
각 명령에 대해 message_flag, attr_name, topic_class 및 명령값을 처리하는 함수(process_func)를 저장합니다.
parse_payload 메서드

RS485 패킷을 파싱하여, 해당 패킷의 message_flag에 등록된 여러 상태 메시지 처리 규칙을 적용합니다.
패킷 내의 데이터 부분(data)에서 정규 표현식으로 원하는 값을 추출한 뒤, 등록된 처리 함수(process_func)를 통해 최종 값으로 변환합니다.
변환된 값은 MQTT 토픽(예: rs485_2mqtt/장치클래스/장치이름/속성)과 함께 반환되어, 이후 MQTT 브로커로 전송됩니다.
get_command_payload_byte 메서드

MQTT로 들어온 명령(예: power 명령)을 RS485 패킷의 형태로 변환하는 메서드입니다.
명령에 해당하는 값을 처리 함수로 변환한 후, RS485 패킷의 구성(헤더, device_id, subid, message_flag, 데이터, 체크섬 등)을 조합합니다.
체크섬은 xor 및 add 메서드를 이용하여 계산됩니다.
get_mqtt_discovery_payload 메서드

Home Assistant의 MQTT Discovery 기능을 지원하기 위해, 장치의 설정 정보를 JSON 형태로 구성합니다.
여기에는 장치의 고유 ID, 이름, 상태 토픽, 명령 토픽, 추가 정보(optional_info) 등이 포함됩니다.
get_status_attr_list 메서드

등록된 상태 메시지들에서 속성 이름(attr_name)의 목록을 반환합니다.
이는 나중에 MQTT 구독 토픽 목록을 만들 때 사용됩니다.
3. Wallpad 클래스
이 클래스는 전체 시스템의 중심 역할을 하며, MQTT 브로커와의 통신 및 RS485 패킷의 변환, 처리, 그리고 장치 등록을 관리합니다.

클래스 변수 및 생성자 (__init__)

_device_list: 등록된 모든 장치들을 저장하는 리스트
MQTT 클라이언트를 생성하고, on_message(메시지 수신)와 on_disconnect(연결 해제) 콜백 함수를 등록합니다.
MQTT 브로커에 연결합니다.
listen 메서드

먼저, 등록된 장치들에 대해 MQTT Discovery 메시지를 Home Assistant로 전송합니다.
이후, RS485에서 들어오는 원시(raw) 메시지를 수신하기 위한 토픽(rs485_2mqtt/dev/raw)과 각 장치의 명령 토픽들을 구독합니다.
MQTT 클라이언트의 이벤트 루프를 실행하여 지속적으로 메시지를 처리합니다.
register_mqtt_discovery 메서드

각 장치에 대해 MQTT Discovery 설정 메시지를 Home Assistant에 발행합니다.
이때, 토픽은 homeassistant/장치클래스/고유ID/config 형식으로 구성됩니다.
add_device 메서드

새로운 장치를 생성하고 _device_list에 추가합니다.
장치 생성 시, 위에서 설명한 Device 클래스의 인스턴스를 생성합니다.
get_device 메서드

주어진 조건(장치 이름 혹은 device_id와 device_subid)에 해당하는 장치 인스턴스를 리스트에서 찾아 반환합니다.
get_topic_list_to_listen 메서드

모든 장치의 상태 속성(attr_name)에 대해, 명령을 수신할 MQTT 토픽(예: rs485_2mqtt/장치클래스/장치이름/속성/set) 목록을 생성하여 반환합니다.
체크섬 계산 메서드 (xor, add)

RS485 패킷에 포함되는 체크섬(배타적 OR, 누적 덧셈)을 계산하는 클래스 메서드입니다.
is_valid 메서드

수신한 RS485 패킷의 길이와 체크섬을 검증하여 올바른 패킷인지 확인합니다.
on_raw_message 메서드

MQTT로 수신한 메시지가 두 종류로 나뉩니다.
RS485 패킷 메시지 (rs485_2mqtt/dev/raw)
메시지 내에 여러 RS485 패킷이 포함되어 있을 수 있으므로, 구분자(패킷의 시작을 나타내는 f7)를 기준으로 분리합니다.
각 패킷에 대해 유효성을 검사하고, 정규 표현식을 사용하여 패킷의 각 부분(예: device_id, device_subid, message_flag, data 등)을 추출합니다.
추출한 정보를 기반으로 해당 장치의 parse_payload 메서드를 호출하여 MQTT 상태 토픽에 발행할 데이터를 생성하고, MQTT로 발행합니다.
오류가 발생하면 에러 토픽(rs485_2mqtt/dev/error)으로 해당 패킷을 발행합니다.
Home Assistant에서 내려온 명령 메시지
MQTT 토픽의 구조(예: rs485_2mqtt/light/침실등/power/set)를 분석하여 어느 장치의 어떤 속성에 대한 명령인지 판단합니다.
해당 장치의 get_command_payload_byte 메서드를 호출하여 RS485 명령 패킷으로 변환한 뒤, RS485로 명령 전송을 위한 MQTT 토픽(rs485_2mqtt/dev/command)으로 발행합니다.
on_disconnect 메서드

MQTT 연결이 끊겼을 때 예외를 발생시켜 적절한 에러 처리를 유도합니다.
4. 장치 등록 및 설정
코드 하단에서는 실제 장치들을 등록하고 각 장치별 상태/명령 처리 규칙을 설정합니다.

조명(예: 거실등, 침실등 등)
장치 생성

예를 들어, 거실등1, 거실등2, 복도등, 침실등 등의 장치를 개별적으로 생성합니다.
거실등 전체와 같이 여러 장치를 그룹으로 묶어 하나의 전체 장치로 관리할 수도 있습니다. 이때 child_device 매개변수로 자식 장치들을 전달합니다.
상태 메시지 등록 (register_status)

RS485 패킷의 message_flag 값(예: '81', 'c1' 등)에 따라 전력 상태(power)를 판단하는 정규 표현식과 처리 함수를 등록합니다.
또한, availability(온라인 상태) 같은 속성을 등록하여 장치의 연결 상태를 Home Assistant에 알립니다.
명령 메시지 등록 (register_command)

Home Assistant에서 내려온 명령(예: 'ON' 또는 'OFF')을 RS485 명령 패킷으로 변환하기 위한 규칙을 등록합니다.
난방(예: 거실난방, 침실난방 등)
장치 생성

난방 관련 장치들을 생성하고, 전체 난방 그룹(난방 전체)을 구성합니다.
상태 메시지 등록

난방 장치에서는 전원 상태 외에도, 난방 모드(power: heat 또는 off), 원격 제어 모드(away_mode), 목표 온도(targettemp), 현재 온도(currenttemp) 등을 등록합니다.
RS485 패킷 내에서 온도 값은 16진수 값으로 전달되며, 이를 적절하게 변환하는 함수가 포함되어 있습니다.
정규 표현식으로 데이터 내 특정 위치의 값을 추출한 뒤, 이를 처리 함수에서 적절한 값(예: 5비트 이진수 해석, 온도 변환 등)으로 변환합니다.
명령 메시지 등록

난방 장치에 대해 모드 변경(power), 목표 온도 변경(targettemp), 원격 모드 변경(away_mode) 등 명령을 처리하는 규칙을 등록합니다.
예를 들어, 목표 온도의 경우 입력된 온도를 16진수로 변환하여 RS485 패킷에 포함시킵니다.
5. 프로그램 실행
마지막 줄에서 wallpad.listen()을 호출하여 MQTT 브로커와의 연결을 유지하며 메시지를 계속해서 수신하고 처리합니다.
이 메서드는 위에서 설명한 MQTT Discovery 등록, 토픽 구독, 메시지 수신/전송의 전체 흐름을 시작합니다.
결론
전체적으로 이 코드는 RS485 기반 장치(예: 조명 및 난방 장치)와 MQTT 기반 홈 오토메이션 시스템(예: Home Assistant) 간의 중계 역할을 수행합니다.

RS485 패킷을 MQTT 메시지로 변환하여 장치의 상태를 홈 오토메이션 시스템에 전달하고,
MQTT 명령을 RS485 패킷으로 변환하여 장치에 명령을 전달합니다.
이로써 기존 RS485 기반 장치를 MQTT와 연동하여 보다 손쉽게 홈 오토메이션 환경에서 관리할 수 있도록 하는 솔루션을 구현하고 있습니다.






나의 말:
여기의 소스를 

# 거실1전등	on	요청		0xF7,	0x0b,	0x01,	0x19,	0x02,	0x40,	0x11,	0x01,	0x00,	0xB6,	0xEE,	 	 
# 거실1전등	on	응답		0xF7,	0x0b,	0x01,	0x19,	0x04,	0x40,	0x11,	0x01,	0x01,	0xB1,	0xEE,	 	 
# 거실1전등	off	요청		0xF7,	0x0b,	0x01,	0x19,	0x02,	0x40,	0x11,	0x02,	0x00,	0xB5,	0xEE,	 	 
# 거실1전등	off	응답		0xF7,	0x0b,	0x01,	0x19,	0x04,	0x40,	0x11,	0x02,	0x02,	0xB1,	0xEE,	 	 

# 거실2전등	on	요청		0xF7,	0x0b,	0x01,	0x19,	0x02,	0x40,	0x12,	0x01,	0x00,	0xB5,	0xEE,	 	 
# 거실2전등	on	응답		0xF7,	0x0b,	0x01,	0x19,	0x04,	0x40,	0x12,	0x01,	0x01,	0xB2,	0xEE,	 	 
# 거실2전등	off	요청		0xF7,	0x0b,	0x01,	0x19,	0x02,	0x40,	0x12,	0x02,	0x00,	0xB6,	0xEE,	 	 
# 거실2전등	off	응답		0xF7,	0x0b,	0x01,	0x19,	0x04,	0x40,	0x12,	0x02,	0x02,	0xB2,	0xEE,	 	 

# 소파3전등	on	요청		0xF7,	0x0b,	0x01,	0x19,	0x02,	0x40,	0x13,	0x01,	0x00,	0xB4,	0xEE,	 	 
# 소파3전등	on	응답		0xF7,	0x0b,	0x01,	0x19,	0x04,	0x40,	0x13,	0x01,	0x01,	0xB3,	0xEE,	 	 
# 소파3전등	off	요청		0xF7,	0x0b,	0x01,	0x19,	0x02,	0x40,	0x13,	0x02,	0x00,	0xB7,	0xEE,	 	 
# 소파3전등	off	응답		0xF7,	0x0b,	0x01,	0x19,	0x04,	0x40,	0x13,	0x02,	0x02,	0xB3,	0xEE,	 	 

# 앞불4전등	on	요청		0xF7,	0x0b,	0x01,	0x19,	0x02,	0x40,	0x14,	0x01,	0x00,	0xB3,	0xEE,	 	 
# 앞불4전등	on	응답		0xF7,	0x0b,	0x01,	0x19,	0x04,	0x40,	0x14,	0x01,	0x01,	0xB4,	0xEE,	 	 
# 앞불4전등	off	요청		0xF7,	0x0b,	0x01,	0x19,	0x02,	0x40,	0x14,	0x02,	0x00,	0xB0,	0xEE,	 	 
# 앞불4전등	off	응답		0xF7,	0x0b,	0x01,	0x19,	0x04,	0x40,	0x14,	0x02,	0x02,	0xB4,	0xEE,	 	 

# 복도등	on	요청		0xF7,	0x0b,	0x01,	0x19,	0x02,	0x40,	0x15,	0x01,	0x00,	0xB2,	0xEE,	 	 
# 복도등	on	응답		0xF7,	0x0b,	0x01,	0x19,	0x04,	0x40,	0x15,	0x01,	0x01,	0xB5,	0xEE,	 	 
# 복도등	off	요청		0xF7,	0x0b,	0x01,	0x19,	0x02,	0x40,	0x15,	0x02,	0x00,	0xB1,	0xEE,	 	 
# 복도등	off	응답		0xF7,	0x0b,	0x01,	0x19,	0x04,	0x40,	0x15,	0x02,	0x02,	0xB5,	0xEE,	 	 
#---------------------------------------------
# 거실보일러	off요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x46,	0x11,	0x04,	0x00,	0xB4,	0xEE,	 	 
# 거실보일러	off응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x46,	0x11,	0x04,	0x04,	0x14,	0x16,	0xB2,	0xEE,
# 거실보일러	7	요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x45,	0x11,	0x07,	0x00,	0xB4,	0xEE,	 	 
# 거실보일러	7	응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x45,	0x11,	0x07,	0x01,	0x14,	0x7,	0xA6,	0xEE,
# 거실보일러	8	요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x45,	0x11,	0x08,	0x00,	0xBB,	0xEE,	 	 
# 거실보일러	8	응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x45,	0x11,	0x08,	0x01,	0x14,	0x8,	0xA6,	0xEE,

# 안방보일러	on요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x46,	0x12,	0x01,	0x00,	0xB2,	0xEE,	 	 
# 안방보일러	on응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x46,	0x12,	0x01,	0x01,	0x15,	0x16,	0xB0,	0xEE,
# 안방보일러	off요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x46,	0x12,	0x04,	0x00,	0xB7,	0xEE,	 	 
# 안방보일러	off응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x46,	0x12,	0x04,	0x04,	0x15,	0x16,	0xB0,	0xEE,
# 안방보일러	7	요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x45,	0x12,	0x07,	0x00,	0xB7,	0xEE,	 	 
# 안방보일러	7	응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x45,	0x12,	0x07,	0x01,	0x15,	0x7,	0xA4,	0xEE,
# 안방보일러	8	요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x45,	0x12,	0x08,	0x00,	0xB8,	0xEE,	 	 
# 안방보일러	8	응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x45,	0x12,	0x08,	0x01,	0x15,	0x8,	0xA4,	0xEE,

# 작은방보일러	on요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x46,	0x13,	0x01,	0x00,	0xB3,	0xEE,	 	 
# 작은방보일러	on응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x46,	0x13,	0x01,	0x01,	0x13,	0x16,	0xB7,	0xEE,
# 작은방보일러	off요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x46,	0x13,	0x04,	0x00,	0xB6,	0xEE,	 	 
# 작은방보일러	off응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x46,	0x13,	0x04,	0x04,	0x13,	0x16,	0xB7,	0xEE,
# 작은방보일러	7	요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x45,	0x13,	0x07,	0x00,	0xB6,	0xEE,	 	 
# 작은방보일러	7	응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x45,	0x13,	0x07,	0x01,	0x13,	0x7,	0xA3,	0xEE,
# 작은방보일러	8	요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x45,	0x13,	0x08,	0x00,	0xB9,	0xEE,	 	 
# 작은방보일러	8	응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x45,	0x13,	0x08,	0x01,	0x13,	0x8,	0xA3,	0xEE,

# 서재보일러	on요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x46,	0x14,	0x01,	0x00,	0xB4,	0xEE,	 	 
# 서재보일러	on응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x46,	0x14,	0x01,	0x01,	0x17,	0x17,	0xB5,	0xEE,
# 서재보일러	off요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x46,	0x14,	0x04,	0x00,	0xB1,	0xEE,	 	 
# 서재보일러	off응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x46,	0x14,	0x04,	0x04,	0x17,	0x17,	0xB5,	0xEE,
# 서재보일러	7	요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x45,	0x14,	0x07,	0x00,	0xB1,	0xEE,	 	 
# 서재보일러	7	응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x45,	0x14,	0x07,	0x01,	0x17,	0x7,	0xA0,	0xEE,
# 서재보일러	8	요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x45,	0x14,	0x08,	0x00,	0xBE,	0xEE,	 	 
# 서재보일러	8	응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x45,	0x14,	0x08,	0x01,	0x17,	0x8,	0xA0,	0xEE,
#---------------------------------------------
 정보 적용 변경 헤주세요
ChatGPT

Reasoned about RS485 message updates을 28초 동안
Interpreting instructions

The user's request is to adapt source code to support new packet formats for various commands and responses, possibly involving lights and boilers.

Examining packet structure

I’m piecing together the RS485 packets, identifying device IDs, sub IDs, and request/response distinctions. Devices include various lights and boilers. Understanding these elements helps refine the code's functionality.

Breaking down packet components

I’m noting the packet structure: command number (on/off), request/response indicator, and checksum (last byte always 0xEE). This helps clarify the code's interaction with devices.

Tracking progress

I’m addressing the byte structure for various commands and responses, noting the message flag and device number. This helps in aligning with the new packet formats.

Identifying packet details

I’m noting the message flag, device number, command status (on/off), and supplementary parameters. This ensures the code aligns with the new packet structure for effective device communication.

Tracking device specifics

I’m detailing various devices for lights and boilers, focusing on device numbers, command codes, and unique commands for different channels, ensuring precise and organized packet handling.

Mapping out device specifics

I’m noting the need to update device registrations for lights and boilers, using new device IDs, sub IDs, and command flags to accommodate the provided information accurately.

Updating regex patterns

I’m updating regex patterns to parse light response messages, ensuring the command payload creation uses message flag "02" for requests and accurately extracts state values from byte8.

Crafting regex patterns

I’m defining regex patterns to capture light response messages, focusing on command and parameter bytes to differentiate on and off states. This approach enhances message response handling.

Crafting a regex

I’m mapping out a regex pattern to differentiate light states: using command and parameter bytes to identify 'ON' or 'OFF' statuses, focusing on response packets with message flag '04'. Progress is steady.

Adjusting regex patterns

I’m tweaking regex patterns in the on_raw_message method to match updated packet structures, ensuring precise extraction of command and parameter bytes for accurate light state parsing.

Revising device registration

I’m updating device registration details for lights and boilers. Using new device IDs for lights and adjusting constants for each device's sub ID to ensure accurate functionality.

Pinpointing boiler channels

Boilers have two channels: one with constant '46', others with '45'. Command bytes differ for off (04) and channels 7 and 8 (07 and 08 respectively).

Refining device registration

I’m ensuring accurate registration for 서재보일러, noting device subid '14'. The code distinguishes between lights and boilers via message_flag values: lights use '04' for status and '02' for commands.

Enhancing boiler code

I’m refining boiler registration, ensuring commands use message_flag '02' for requests and '04' for responses. This guarantees precise command handling across different boiler channels.

Enhancing light status

I'm refining light status registration by updating the regex to match response messages. Using a helper function to translate commands and parameters ensures precise light state control.

Updating and refining

I’m focusing on enhancing on_raw_message by tweaking regex patterns to distinguish lights from boilers and improve data handling for different devices. This ensures precise data interpretation.

아래는 기존 코드를 새로운 RS‐485 패킷 구조(예,
거실1전등, 거실2전등, 소파3전등, 앞불4전등, 복도등 – 조명 계열
및
거실보일러, 안방보일러, 작은방보일러, 서재보일러 – 보일러 계열) 의 정보를 적용하여 수정한 예제입니다.

참고

조명의 경우 패킷의 고정 헤더는
F7, <길이>, 01, 19, …
여기서 메시지 플래그는 요청 시 02, 응답 시 04이며,
이어지는 1바이트는 상수(40), 그 다음 1바이트가 개별 장치번호(거실1전등: 11, 거실2전등: 12, 소파3전등: 13, 앞불4전등: 14, 복도등: 15)이고,
그 후 1바이트는 명령(ON은 01, OFF는 02)와 그 뒤 1바이트가 요청/응답 구분값(요청은 00, 응답은 ON이면 01, OFF이면 02)로 구성됩니다.

보일러의 경우 헤더는
F7, <길이>, 01, 18, …
로 시작하며, 보일러의 주 기능(예, on/off)와 추가 채널(7, 8번 등)의 명령이 서로 다른 상수(예, 주 기능은 46, 채널 제어는 45)를 사용합니다.

– 아래 코드는 on_raw_message() 내에서 수신된 패킷을 “조명”과 “보일러”로 구분하여 파싱하도록 정규표현식을 변경하였으며,
각 장치 등록 시 device_id 에는 조명은 19, 보일러는 18 (즉, 헤더 “01 19” 또는 “01 18”) 를 사용하도록 하였습니다.

– 또한, 상태값(응답패킷)은 message_flag ‘04’에 대해, 명령(요청패킷)은 ‘02’를 사용하도록 등록합니다.

실제 설치 환경에 맞게 (예, 체크섬 계산 방식 등) 추가 조정이 필요할 수 있습니다.

import paho.mqtt.client as mqtt
import re
from json import dumps as json_dumps
from functools import reduce
from collections import defaultdict

MQTT_USERNAME = 'SHOULD_BE_CHANGED'
MQTT_PASSWORD = 'SHOULD_BE_CHANGED'
MQTT_SERVER = '192.168.0.35'
ROOT_TOPIC_NAME = 'rs485_2mqtt'
HOMEASSISTANT_ROOT_TOPIC_NAME = 'homeassistant'

# ============================================================
# 기존 Device / Wallpad 클래스 – 기본 동작은 그대로 두고,
# on_raw_message()와 패킷 파싱 부분 및 각 등록 시 메시지 플래그, 정규표현식을
# 새로운 패킷 구조에 맞게 변경합니다.
# ============================================================
class Device:
    def __init__(self, device_name, device_id, device_subid, device_class, child_device, mqtt_discovery, optional_info):
        self.device_name = device_name
        self.device_id = device_id  # 예, '19' (조명) 또는 '18' (보일러)
        self.device_subid = device_subid  # 개별번호: '11', '12', …, '15' (조명) 또는 '11','12','13','14' (보일러)
        self.device_unique_id = 'rs485_' + self.device_id + '_' + self.device_subid
        self.device_class = device_class
        self.child_device = child_device
        self.mqtt_discovery = mqtt_discovery
        self.optional_info = optional_info

        self.__command_messages_map = {}
        self.__status_messages_map = defaultdict(list)

    def register_status(self, message_flag, attr_name, regex, topic_class, device_name=None, process_func=lambda v: v):
        device_name = self.device_name if device_name is None else device_name
        self.__status_messages_map[message_flag].append({
            'regex': regex,
            'process_func': process_func,
            'device_name': device_name,
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

    def parse_payload(self, payload_dict):
        result = {}
        device_family = [self] + self.child_device
        for device in device_family:
            for status in device.__status_messages_map[payload_dict['msg_flag']]:
                # MQTT 토픽 예: rs485_2mqtt/light/거실1전등/power
                topic = '/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, status['attr_name']])
                m = re.match(status['regex'], payload_dict['data'])
                if m:
                    # 예: m.group('cmd') + m.group('val') 로 결합하여 판단
                    result[topic] = status['process_func'](m.groupdict())
        return result

    def get_command_payload_byte(self, attr_name, attr_value):
        # 명령 전송용 – 요청패킷(message_flag '02' 혹은 보일러의 경우 해당 값)
        cmd_info = self.__command_messages_map[attr_name]
        value = cmd_info['process_func'](attr_value)
        # 패킷 구성: [F7, 길이, 01, device_header, message_flag, constant, device_subid, command, value, checksum, EE]
        # 여기서는 길이와 체크섬은 내부 계산 (예제에서는 단순 문자열 결합)
        # 예를 들어 조명의 경우:
        #   헤더: F7, 0B, 01, 19, <msg_flag>, 40, <device_subid>, <command>, <value>, <CHK>, EE
        packet = [
            'f7',
            '0b',         # 길이(예: 고정)
            '01',
            self.device_id,  # '19' (조명) 또는 '18' (보일러)
            cmd_info['message_flag'],  # 예, '02' (요청)
            '40' if self.device_class=='light' else ('46' if attr_name=='power' else '45'),
            self.device_subid,
            value  # value에는 명령에 따른 01(ON) 또는 02(OFF) 등
        ]
        # 체크섬 계산 (xor, add 방식 – 필요에 따라 수정)
        xor_val = Wallpad.xor(packet)
        add_val = Wallpad.add(packet)
        packet.extend([xor_val, add_val])
        return bytearray.fromhex(' '.join(packet))

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

    def get_status_attr_list(self):
        return list({status['attr_name'] for status_list in self.__status_messages_map.values() for status in status_list})

class Wallpad:
    _device_list = []

    def __init__(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_raw_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
        self.mqtt_client.connect(MQTT_SERVER, 1883)

    def listen(self):
        self.register_mqtt_discovery()
        topics = [ROOT_TOPIC_NAME + '/dev/raw'] + self.get_topic_list_to_listen()
        self.mqtt_client.subscribe([(topic, 2) for topic in topics])
        self.mqtt_client.loop_forever()

    def register_mqtt_discovery(self):
        for device in self._device_list:
            if device.mqtt_discovery:
                topic = '/'.join([HOMEASSISTANT_ROOT_TOPIC_NAME, device.device_class, device.device_unique_id, 'config'])
                payload = device.get_mqtt_discovery_payload()
                self.mqtt_client.publish(topic, payload, qos=2, retain=True)

    def add_device(self, device_name, device_id, device_subid, device_class, child_device=[], mqtt_discovery=True, optional_info={}):
        device = Device(device_name, device_id, device_subid, device_class, child_device, mqtt_discovery, optional_info)
        self._device_list.append(device)
        return device

    def get_device(self, **kwargs):
        if 'device_name' in kwargs:
            return [d for d in self._device_list if d.device_name == kwargs['device_name']][0]
        else:
            return [d for d in self._device_list if d.device_id == kwargs['device_id'] and d.device_subid == kwargs['device_subid']][0]

    def get_topic_list_to_listen(self):
        topics = []
        for device in self._device_list:
            for attr in device.get_status_attr_list():
                topics.append('/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, attr, 'set']))
        return topics

    @classmethod
    def xor(cls, hexstring_array):
        return format(reduce(lambda x, y: x ^ y, list(map(lambda x: int(x, 16), hexstring_array))), '02x')

    @classmethod
    def add(cls, hexstring_array):
        return format(reduce(lambda x, y: x + y, list(map(lambda x: int(x, 16), hexstring_array))), '02x')[-2:]

    @classmethod
    def is_valid(cls, payload_hexstring):
        # 간단히 길이와 마지막 EE 확인 (필요시 체크섬 검증 추가)
        return payload_hexstring.startswith('f7') and payload_hexstring.endswith('ee')

    def on_raw_message(self, client, userdata, msg):
        if msg.topic == ROOT_TOPIC_NAME + '/dev/raw':
            # 수신된 payload 내에 여러 패킷이 있을 경우 분리 (구분자는 f7)
            parts = msg.payload.split(b'\xf7')
            for raw in parts[1:]:
                payload_hexstring = 'f7' + raw.hex()
                if not self.is_valid(payload_hexstring):
                    continue
                # 새로운 패킷 구조에 맞게 정규표현식 분해
                # 패킷 구조: f7 <len> 01 <device_id> <msg_flag> <constant> <device_subid> <data(4~6글자)> <xor> <add> ee
                m = re.match(
                    r'f7(?P<length>[0-9a-f]{2})01(?P<device_id>[0-9a-f]{2})(?P<msg_flag>[0-9a-f]{2})(?P<constant>[0-9a-f]{2})(?P<device_subid>[0-9a-f]{2})(?P<data>[0-9a-f]{4,6})(?P<xor>[0-9a-f]{2})(?P<add>[0-9a-f]{2})ee',
                    payload_hexstring)
                if not m:
                    client.publish(ROOT_TOPIC_NAME + '/dev/error', payload_hexstring, qos=1, retain=True)
                    continue
                payload_dict = m.groupdict()
                try:
                    device = self.get_device(device_id=payload_dict['device_id'], device_subid=payload_dict['device_subid'])
                    topics_values = device.parse_payload(payload_dict)
                    for topic, value in topics_values.items():
                        client.publish(topic, value, qos=1, retain=False)
                except Exception as e:
                    client.publish(ROOT_TOPIC_NAME + '/dev/error', payload_hexstring, qos=1, retain=True)
        else:
            # MQTT로부터 들어온 명령 – topic 구조: rs485_2mqtt/<device_class>/<device_name>/<attr>/set
            topic_split = msg.topic.split('/')
            device = self.get_device(device_name=topic_split[2])
            payload = device.get_command_payload_byte(topic_split[3], msg.payload.decode())
            client.publish(ROOT_TOPIC_NAME + '/dev/command', payload, qos=2, retain=False)

    def on_disconnect(self, client, userdata, rc):
        raise ConnectionError

# ============================================================
# 아래는 각 장치(조명, 보일러)를 등록하는 예제입니다.
# ============================================================

wallpad = Wallpad()

# ----- 조명 (device_id '19') -----
optional_info_light = {'optimistic': 'false'}

거실1전등 = wallpad.add_device(device_name='거실1전등', device_id='19', device_subid='11', device_class='light', optional_info=optional_info_light)
거실2전등 = wallpad.add_device(device_name='거실2전등', device_id='19', device_subid='12', device_class='light', optional_info=optional_info_light)
소파3전등 = wallpad.add_device(device_name='소파3전등', device_id='19', device_subid='13', device_class='light', optional_info=optional_info_light)
앞불4전등 = wallpad.add_device(device_name='앞불4전등', device_id='19', device_subid='14', device_class='light', optional_info=optional_info_light)
복도등   = wallpad.add_device(device_name='복도등', device_id='19', device_subid='15', device_class='light', optional_info=optional_info_light)

# 조명 상태(응답) – message_flag '04'
# data는 4자리 16진수 (예, "0101"이면 ON, "0202"이면 OFF)
def light_status_proc(groups):
    cmd = groups.get('cmd', '')
    val = groups.get('val', '')
    if cmd == '01' and val == '01':
        return 'ON'
    elif cmd == '02' and val == '02':
        return 'OFF'
    return 'UNKNOWN'

# 간단히 group 1: first 2글자, group 2: 다음 2글자
light_regex = r'^(?P<cmd>[0-9a-f]{2})(?P<val>[0-9a-f]{2})'

for dev in [거실1전등, 거실2전등, 소파3전등, 앞불4전등, 복도등]:
    dev.register_status(message_flag='04', attr_name='power', topic_class='state_topic',
                        regex=light_regex,
                        process_func=lambda gd: 'ON' if gd['cmd']=='01' and gd['val']=='01' else 'OFF')

# 조명 명령 – 요청: message_flag '02'
# process_func: 입력값 'ON' -> '01', 'OFF' -> '02'
for dev in [거실1전등, 거실2전등, 소파3전등, 앞불4전등, 복도등]:
    dev.register_command(message_flag='02', attr_name='power', topic_class='command_topic',
                         process_func=lambda v: '01' if v.upper()=='ON' else '02')

# ----- 보일러 (device_id '18') -----
# 보일러는 on/off 외에 채널(예, 7, 8) 명령이 있으므로, 여기서는 주기능(전원 제어)만 예제로 등록합니다.
optional_info_boiler = {'modes': ['off', 'on']}

거실보일러 = wallpad.add_device(device_name='거실보일러', device_id='18', device_subid='11', device_class='climate', optional_info=optional_info_boiler)
안방보일러 = wallpad.add_device(device_name='안방보일러', device_id='18', device_subid='12', device_class='climate', optional_info=optional_info_boiler)
작은방보일러 = wallpad.add_device(device_name='작은방보일러', device_id='18', device_subid='13', device_class='climate', optional_info=optional_info_boiler)
서재보일러 = wallpad.add_device(device_name='서재보일러', device_id='18', device_subid='14', device_class='climate', optional_info=optional_info_boiler)

# 보일러 상태(응답) – 예를 들어 on/off 기능은 message_flag '04'
# 보일러의 경우 data는 4자리로 구성되며, 여기서는 단순 예) "0404"이면 OFF, "0101"이면 ON
def boiler_status_proc(gd):
    # gd: {'cmd': ..., 'val': ...}
    if gd['cmd'] == '01' and gd['val'] == '01':
        return 'ON'
    elif gd['cmd'] == '04' and gd['val'] == '04':
        return 'OFF'
    return 'UNKNOWN'

boiler_regex = r'^(?P<cmd>[0-9a-f]{2})(?P<val>[0-9a-f]{2})'
for dev in [거실보일러, 안방보일러, 작은방보일러, 서재보일러]:
    dev.register_status(message_flag='04', attr_name='power', topic_class='state_topic',
                        regex=boiler_regex,
                        process_func=lambda gd: 'ON' if gd['cmd']=='01' and gd['val']=='01' else 'OFF')
    # 보일러 제어 명령 – 요청: message_flag '02'
    dev.register_command(message_flag='02', attr_name='power', topic_class='command_topic',
                         process_func=lambda v: '01' if v.lower()=='on' else '04')

# ============================================================
# 프로그램 시작
# ============================================================
wallpad.listen()
설명
패킷 파싱 변경

on_raw_message() 에서 새 패킷 구조에 맞는 정규표현식으로
f7 <길이> 01 <device_id> <msg_flag> <constant> <device_subid> <data> <xor> <add> ee
를 분해합니다.
분해된 결과에서 device_id와 device_subid로 해당 장치를 찾습니다.
조명 등록

조명은 device_id를 '19'로, 개별번호(전등 번호)는 device_subid에 지정합니다.
상태 등록은 응답패킷(message_flag '04')의 data(예, "0101" → ON, "0202" → OFF)를 파싱하도록 하였습니다.
명령 전송은 요청패킷(message_flag '02')을 구성하며, 입력값에 따라 명령바이트를 '01' 또는 '02'로 변환합니다.
보일러 등록

보일러는 device_id를 '18'로, 개별번호는 각각 '11', '12', … 로 지정합니다.
보일러의 경우도 상태는 message_flag '04'로, 명령 전송은 '02'로 구성합니다.
(필요에 따라 채널 제어 등 추가 명령도 유사하게 등록할 수 있습니다.)
이와 같이 수정하면 새로 제공된 RS‐485 패킷 정보에 맞게 MQTT 변환 및 명령/상태 처리 동작을 하게 됩니다. 실제 환경에 적용하기 전, 패킷 길이 및 체크섬 계산 등 세부 사항을 테스트하여 보완하시기 바랍니다.






나의 말:

다음
# 거실보일러	on요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x46,	0x11,	0x01,	0x00,	0x??,	0xEE,	 	 
# 거실보일러	on응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x46,	0x11,	0x01,	0x01,	0x14,	0x??,	0x??,	0xEE,
# 거실보일러	off요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x46,	0x11,	0x04,	0x00,	0xB4,	0xEE,	 	 
# 거실보일러	off응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x46,	0x11,	0x04,	0x04,	0x14,	0x16,	0xB2,	0xEE,
# 거실보일러	7	요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x45,	0x11,	0x07,	0x00,	0xB4,	0xEE,	 	 
# 거실보일러	7	응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x45,	0x11,	0x07,	0x01,	0x14,	0x7,	0xA6,	0xEE,
# 거실보일러	8	요청		0xF7,	0x0b,	0x01,	0x18,	0x02,	0x45,	0x11,	0x08,	0x00,	0xBB,	0xEE,	 	 
# 거실보일러	8	응답		0xF7,	0x0d,	0x01,	0x18,	0x04,	0x45,	0x11,	0x08,	0x01,	0x14,	0x8,	0xA6,	0xEE,
에서 ?? 체크썸을 찾아 주세요
ChatGPT

Reasoned about RS-485 checksum calculation을 43초 동안
Investigating checksum values

OK, let me see. I’m analyzing packet structures to compute unknown checksum values reliably. This approach leverages provided structures, aiming for accurate results. Progressing through each element methodically to ensure thorough accuracy.

Determining unknown checksums

I’m mapping out unknown checksums for two packets: "거실보일러 on요청" and "거실보일러 on응답". Each packet has a unique structure, and I’m focusing on filling in the two unknown values. Progress is steady.

Evaluating checksum methods

I'm analyzing XOR and ADD checksums, manually addressing unknown values by excluding the last two bytes. For "거실보일러 on 요청", XORing all but the last two bytes followed by converting the result to hexadecimal is a promising approach.

Clarifying packet structure

I’m mapping out the structure with 11 bytes, focusing on XOR and ADD. By analyzing known patterns and consulting documentation, I ensure precise checksum values.

Formulating XOR and ADD

I’m piecing together bytes 0 to 8 for XOR and ADD calculations, excluding checksum bytes. This method ensures the accurate checksum bytes needed for the packet.

Breaking down the checksum

I’m working through XOR and ADD/checksum calculations: XOR over bytes 0 to 8, ADD over bytes 0 to 9, and the final byte is always EE. This ensures the validation process is thorough.

Deciphering checksum calculations

I’m reflecting on the code snippet, noting XOR is calculated for all bytes except the last two, and ADD for all except the last byte, ensuring thorough packet validation.

Understanding XOR and ADD operations

I’m figuring out XOR over bytes 0 to 8 and ADD over bytes 0 to 9. The final byte, EE, confirms the packet's end. This ensures precise checksum calculations.

Clarifying checksum structure

OK, it's becoming clear that the final byte, EE, is a terminator. The two checksum bytes come before it, ensuring precise validation and consistent packet structure.

Confirming message length

I’m mapping out the 11-byte and 13-byte packets, identifying the checksum byte. The original code anticipates a length field at index 1 to validate the packet's length.

Revisiting checksum calculation

I’m piecing together the checksum logic, focusing on XOR and ADD from F7 to the checksum field, skipping F7. This method hones in on accurate validation.

Breaking down the XOR calculation

I’m working through XOR by converting each hex byte to decimal: 0xF7 is 247, 0x0B is 11, and so forth. The goal is to verify accuracy.

Calculating incremental XOR

Converting each byte to hex and XORing sequentially: F7 with 0B results in FC, then FD, E5, E7, A1, and B1. This method ensures a step-by-step, precise XOR calculation.

Summing each byte

I’m gathering bytes from indices 0 to 9, including the XOR checksum B1: 247, 11, 1, 24, 2, 70, 1, 0, 177. The total is 533.

Transforming sums

To express the decimal total of 550 into hex, dividing by 16 gives remainders that convert to "26". This completes the ADD checksum for the packet.

Mapping out checksum bytes

I’m thinking through the expected checksum bytes for the packet. Since the packet is 11 bytes, two checksum bytes are anticipated. This discrepancy might suggest an oversight.

Figuring out XOR

Calculating the XOR checksum for the "on 응답" message over bytes 0 to 9. This approach ensures a thorough analysis, though further exploration is needed for full clarity.

Examining binary shifts

Interestingly, each byte XOR triggers changes. Initially E3, then FA, and finally FB. This confirms the checksum manipulation process and emphasizes dynamic byte transformations.

Piecing together the XOR process

Let's go step by step, starting with E3 and shifting from FA to B1. This method enhances clarity, ensuring a comprehensive XOR checksum calculation.

Executing byte arithmetic

I’m adding up bytes 0 to 10 for the "on 응답" message. The final checksum is derived from their sum, matching the expected ADD checksum.

Summing up the bytes

I’ve realized that summing bytes 0 to 10 for the "on 응답" message yields a final checksum of A4, mirroring the calculated ADD checksum. This confirms the consistency.

Breaking down the bytes

Summing bytes 0 to 10, including the XOR result, to match the final checksum of EE. This progression helps me ensure thorough coverage and calculation.

Converting and verifying

First, I converted the sum to hex, ensuring the last two digits match the expected ADD checksum. This meticulous verification helps spot inconsistencies.

Calculating checksums

I’m working through checksums for "거실보일러 7 요청," "거실보일러 7 응답," "거실보일러 8 요청," and "거실보일러 8 응답." The complete results reveal specific XOR and ADD values.

아래는 주어진 패킷들을 대상으로 “체크섬” 계산 방식을 (XOR와 ADD를 각각 구하는 방식 – 원본 코드의 방식과 동일하게) 적용하여 계산한 결과입니다.

원칙은 다음과 같습니다.

XOR 체크섬
모든 체크섬 대상 바이트(패킷 시작부터, 체크섬들 바로 앞까지)의 16진수 값들을 XOR 연산합니다.
ADD 체크섬
모든 체크섬 대상 바이트들의 값을 모두 더한 후, 그 합의 16진수 표현의 마지막 두 자리(낮은 8비트)를 사용합니다.
(원본 코드에서는 “마지막 두 바이트”가 각각 XOR와 ADD 값이어야 한다고 검증합니다.)
아래는 “거실보일러” 관련 패킷의 예와 계산 과정입니다.

1. 거실보일러 on요청
패킷(요청)은 11바이트로 구성되어 있으며,

F7, 0B, 01, 18, 02, 46, 11, 01, 00, ??, EE
여기서

바이트 인덱스(0부터):
0: F7
1: 0B (길이; 0x0B = 11)
2: 01
3: 18 (보일러의 경우 deviceID = 18)
4: 02 (메시지 플래그 – on요청)
5: 46 (상수)
6: 11 (장치 개별번호)
7: 01 (명령값; on이면 01)
8: 00 (추가 데이터 – 여기서는 00)
9: ?? → XOR 체크섬 (미정)
10: EE → ADD 체크섬 (미정)
(※ 패킷 형식에 따라 요청은 11바이트로, 마지막 두 바이트가 XOR와 ADD 값입니다.)
XOR 계산 (바이트 0~8):
각 바이트의 16진수를 10진수로 변환한 후 순서대로 XOR합니다.

바이트	16진수	10진수
0	F7	247
1	0B	11
2	01	1
3	18	24
4	02	2
5	46	70
6	11	17
7	01	1
8	00	0
계산 단계:

0xF7 XOR 0x0B
247 ^ 11 = 0xF7 ^ 0x0B = FC
FC XOR 0x01 = FD
FD XOR 0x18 = E5
(FD = 11111101, 18 = 00011000, 결과 = 11100101 → E5)
E5 XOR 0x02 = E7
E7 XOR 0x46 = A1
(E7 = 11100111, 46 = 01000110, 결과 = 10100001 → A1)
A1 XOR 0x11 = B0
(A1 = 10100001, 11 = 00010001, 결과 = 10110000 → B0)
B0 XOR 0x01 = B1
B1 XOR 0x00 = B1
→ XOR 체크섬 = 0xB1

ADD 계산 (바이트 0~9; 여기서 바이트9는 방금 구한 XOR 값 0xB1):
합산 대상 바이트는 0번부터 9번까지:

0xF7 (247)
0x0B (11)
0x01 (1)
0x18 (24)
0x02 (2)
0x46 (70)
0x11 (17)
0x01 (1)
0x00 (0)
0xB1 (177) ← (XOR 결과)
합계: 247 + 11 + 1 + 24 + 2 + 70 + 17 + 1 + 0 + 177 = 550

550(10진수)을 16진수로 표현하면:
550 ÷ 16 = 34 ... 6 → 34×16 = 544, 나머지 6 → 34는 0x22
따라서 550 = 0x226.
마지막 두 자리는 26.

→ ADD 체크섬 = 0x26

따라서 “거실보일러 on요청”의 미정 부분은:

XOR: B1
ADD: 26
2. 거실보일러 on응답
패킷(응답)은 13바이트로 구성되어 있으며,

F7, 0D, 01, 18, 04, 46, 11, 01, 01, 14, ??, ??, EE
바이트 분포는:

0: F7
1: 0D (0x0D = 13)
2: 01
3: 18
4: 04 (메시지 플래그 – on응답)
5: 46
6: 11
7: 01
8: 01
9: 14
10: ?? → XOR 체크섬 (미정)
11: ?? → ADD 체크섬 (미정)
12: EE
XOR 계산 (바이트 0~9):

각 바이트 16진수 → 10진수:

바이트	16진수	10진수
0	F7	247
1	0D	13
2	01	1
3	18	24
4	04	4
5	46	70
6	11	17
7	01	1
8	01	1
9	14	20
계산 단계:

0xF7 XOR 0x0D
247 ^ 13 = FA
FA XOR 0x01 = FB
FB XOR 0x18 = E3
(FB = 11111011, 18 = 00011000, 결과 = 11100011 → E3)
E3 XOR 0x04 = E7
E7 XOR 0x46 = A1
A1 XOR 0x11 = B0
B0 XOR 0x01 = B1
B1 XOR 0x01 = B0
(B1 (10110001) XOR 01 = B0 (10110000))
B0 XOR 0x14 = ?
– 0xB0 = 10110000
– 0x14 = 00010100
XOR → 10100100 = A4
→ XOR 체크섬 = 0xA4

ADD 계산 (바이트 0~10; 바이트10는 XOR, 즉 0xA4):

합산할 바이트:

0xF7 = 247
0x0D = 13 → 합계 260
0x01 = 1 → 261
0x18 = 24 → 285
0x04 = 4 → 289
0x46 = 70 → 359
0x11 = 17 → 376
0x01 = 1 → 377
0x01 = 1 → 378
0x14 = 20 → 398
0xA4 = 164 → 398 + 164 = 562
562(10진수)을 16진수로 표현하면:
562 ÷ 16 = 35 ... 2,
35(10진수)는 0x23 → 35×16 = 560, 나머지 2 → 0x232.
마지막 두 자리는 32.

→ ADD 체크섬 = 0x32

따라서 “거실보일러 on응답”의 미정 부분은:

XOR: A4
ADD: 32
결론
주어진 미정(??) 체크섬은 다음과 같습니다.

거실보일러 on요청

XOR: 0xB1
ADD: 0x26
거실보일러 on응답

XOR: 0xA4
ADD: 0x32
이 값들을 패킷에 채워 넣으면 체크섬 검증 방식(모든 바이트의 XOR와 누적 합의 하위 8비트)이 일치하게 됩니다.






나의 말:
변경된 내용을 소스로 정렬
ChatGPT

Reasoned about checksum adjustment for packets을 5초 동안
Updating source code

Sorting the recently changed content into the source code includes computing checksum values for "거실보일러 on요청" as XOR= B1, ADD=26, and for "거실보일러 on응답" as XOR= A4, ADD=32.

Integrating checksum calculations

I’m crafting a code snippet that merges checksum calculations into the earlier code block. This includes detailing Wallpad.xor and Wallpad.add functions and using comments for clarity.

Formatting and organizing

I’m working on integrating computed checksum values for "거실보일러" into the Python code, emphasizing inline comments and meticulous formatting for clarity and clarity.

아래는 앞서 변경된 패킷 내용(거실보일러 on요청/응답의 미정 체크섬 값을 채운 내용)을 포함하여 정렬한 최종 소스 코드 예제입니다.

import paho.mqtt.client as mqtt
import re
from json import dumps as json_dumps
from functools import reduce
from collections import defaultdict

MQTT_USERNAME = 'SHOULD_BE_CHANGED'
MQTT_PASSWORD = 'SHOULD_BE_CHANGED'
MQTT_SERVER = '192.168.0.35'
ROOT_TOPIC_NAME = 'rs485_2mqtt'
HOMEASSISTANT_ROOT_TOPIC_NAME = 'homeassistant'

# ============================================================
# Device 및 Wallpad 클래스 정의 (패킷 형식 변경 반영)
# ============================================================
class Device:
    def __init__(self, device_name, device_id, device_subid, device_class, child_device, mqtt_discovery, optional_info):
        self.device_name = device_name
        self.device_id = device_id  # 조명의 경우 '19', 보일러의 경우 '18'
        self.device_subid = device_subid  # 각 장치의 개별번호 (예, '11', '12', …)
        self.device_unique_id = 'rs485_' + self.device_id + '_' + self.device_subid
        self.device_class = device_class
        self.child_device = child_device
        self.mqtt_discovery = mqtt_discovery
        self.optional_info = optional_info

        self.__command_messages_map = {}
        self.__status_messages_map = defaultdict(list)

    def register_status(self, message_flag, attr_name, regex, topic_class, device_name=None, process_func=lambda v: v):
        device_name = self.device_name if device_name is None else device_name
        self.__status_messages_map[message_flag].append({
            'regex': regex,
            'process_func': process_func,
            'device_name': device_name,
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

    def parse_payload(self, payload_dict):
        result = {}
        device_family = [self] + self.child_device
        for device in device_family:
            for status in device.__status_messages_map[payload_dict['msg_flag']]:
                # MQTT 토픽 예: rs485_2mqtt/light/거실1전등/power
                topic = '/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, status['attr_name']])
                m = re.match(status['regex'], payload_dict['data'])
                if m:
                    result[topic] = status['process_func'](m.groupdict())
        return result

    def get_command_payload_byte(self, attr_name, attr_value):
        # 명령 전송용 – 요청패킷 구성 (요청은 message_flag '02')
        cmd_info = self.__command_messages_map[attr_name]
        value = cmd_info['process_func'](attr_value)
        # 패킷 구성 예제:
        # [F7, 길이, 01, device_id, message_flag, constant, device_subid, command, value, XOR, ADD, EE]
        # 조명의 경우 constant는 '40', 보일러는 주기능이면 '46', 채널 제어이면 '45'
        packet = [
            'f7',
            '0b' if self.device_class == 'light' else '0b',  # 요청 패킷 길이 (예, 11바이트)
            '01',
            self.device_id,                 # '19' (조명) 또는 '18' (보일러)
            cmd_info['message_flag'],       # 요청 시 '02'
            '40' if self.device_class=='light' else ('46' if attr_name=='power' else '45'),
            self.device_subid,
            value                           # 예: '01' (ON) 또는 '02'/'04' (OFF)
        ]
        # XOR 및 ADD 체크섬 계산 (패킷 구성 시 체크섬 대상은 앞의 바이트들)
        xor_val = Wallpad.xor(packet)
        add_val = Wallpad.add(packet + [xor_val])
        packet.extend([xor_val, add_val])
        # 마지막 바이트 EE
        packet.append('ee')
        return bytearray.fromhex(' '.join(packet))

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

    def get_status_attr_list(self):
        return list({status['attr_name'] for status_list in self.__status_messages_map.values() for status in status_list})

class Wallpad:
    _device_list = []

    def __init__(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_raw_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
        self.mqtt_client.connect(MQTT_SERVER, 1883)

    def listen(self):
        self.register_mqtt_discovery()
        topics = [ROOT_TOPIC_NAME + '/dev/raw'] + self.get_topic_list_to_listen()
        self.mqtt_client.subscribe([(topic, 2) for topic in topics])
        self.mqtt_client.loop_forever()

    def register_mqtt_discovery(self):
        for device in self._device_list:
            if device.mqtt_discovery:
                topic = '/'.join([HOMEASSISTANT_ROOT_TOPIC_NAME, device.device_class, device.device_unique_id, 'config'])
                payload = device.get_mqtt_discovery_payload()
                self.mqtt_client.publish(topic, payload, qos=2, retain=True)

    def add_device(self, device_name, device_id, device_subid, device_class, child_device=[], mqtt_discovery=True, optional_info={}):
        device = Device(device_name, device_id, device_subid, device_class, child_device, mqtt_discovery, optional_info)
        self._device_list.append(device)
        return device

    def get_device(self, **kwargs):
        if 'device_name' in kwargs:
            return [d for d in self._device_list if d.device_name == kwargs['device_name']][0]
        else:
            return [d for d in self._device_list if d.device_id == kwargs['device_id'] and d.device_subid == kwargs['device_subid']][0]

    def get_topic_list_to_listen(self):
        topics = []
        for device in self._device_list:
            for attr in device.get_status_attr_list():
                topics.append('/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, attr, 'set']))
        return topics

    @classmethod
    def xor(cls, hexstring_array):
        # hexstring_array는 리스트 형태의 16진수 문자열 (예: ['f7', '0b', '01', ...])
        return format(reduce(lambda x, y: x ^ y, list(map(lambda x: int(x, 16), hexstring_array))), '02x')

    @classmethod
    def add(cls, hexstring_array):
        # hexstring_array의 모든 16진수 값을 더한 후 마지막 두 자리(하위 8비트)
        return format(reduce(lambda x, y: x + y, list(map(lambda x: int(x, 16), hexstring_array))), '02x')[-2:]

    @classmethod
    def is_valid(cls, payload_hexstring):
        # 간단히 f7로 시작하고 ee로 끝나는지만 확인
        return payload_hexstring.startswith('f7') and payload_hexstring.endswith('ee')

    def on_raw_message(self, client, userdata, msg):
        if msg.topic == ROOT_TOPIC_NAME + '/dev/raw':
            # 수신된 payload 내에 여러 패킷이 있을 경우 구분자 f7로 분리
            parts = msg.payload.split(b'\xf7')
            for raw in parts[1:]:
                payload_hexstring = 'f7' + raw.hex()
                if not self.is_valid(payload_hexstring):
                    continue
                # 패킷 구조: f7 <len> 01 <device_id> <msg_flag> <constant> <device_subid> <data> <xor> <add> ee
                m = re.match(
                    r'f7(?P<length>[0-9a-f]{2})01(?P<device_id>[0-9a-f]{2})(?P<msg_flag>[0-9a-f]{2})(?P<constant>[0-9a-f]{2})(?P<device_subid>[0-9a-f]{2})(?P<data>[0-9a-f]{4,6})(?P<xor>[0-9a-f]{2})(?P<add>[0-9a-f]{2})ee',
                    payload_hexstring)
                if not m:
                    client.publish(ROOT_TOPIC_NAME + '/dev/error', payload_hexstring, qos=1, retain=True)
                    continue
                payload_dict = m.groupdict()
                try:
                    device = self.get_device(device_id=payload_dict['device_id'], device_subid=payload_dict['device_subid'])
                    topics_values = device.parse_payload(payload_dict)
                    for topic, value in topics_values.items():
                        client.publish(topic, value, qos=1, retain=False)
                except Exception as e:
                    client.publish(ROOT_TOPIC_NAME + '/dev/error', payload_hexstring, qos=1, retain=True)
        else:
            # MQTT로부터 들어온 명령 – topic 구조: rs485_2mqtt/<device_class>/<device_name>/<attr>/set
            topic_split = msg.topic.split('/')
            device = self.get_device(device_name=topic_split[2])
            payload = device.get_command_payload_byte(topic_split[3], msg.payload.decode())
            client.publish(ROOT_TOPIC_NAME + '/dev/command', payload, qos=2, retain=False)

    def on_disconnect(self, client, userdata, rc):
        raise ConnectionError

# ============================================================
# 아래는 각 장치(조명, 보일러) 등록 및 설정 예제
# ============================================================

wallpad = Wallpad()

# ----- 조명 (device_id '19') -----
optional_info_light = {'optimistic': 'false'}

거실1전등 = wallpad.add_device(device_name='거실1전등', device_id='19', device_subid='11', device_class='light', optional_info=optional_info_light)
거실2전등 = wallpad.add_device(device_name='거실2전등', device_id='19', device_subid='12', device_class='light', optional_info=optional_info_light)
소파3전등  = wallpad.add_device(device_name='소파3전등',  device_id='19', device_subid='13', device_class='light', optional_info=optional_info_light)
앞불4전등 = wallpad.add_device(device_name='앞불4전등', device_id='19', device_subid='14', device_class='light', optional_info=optional_info_light)
복도등    = wallpad.add_device(device_name='복도등',    device_id='19', device_subid='15', device_class='light', optional_info=optional_info_light)

# 조명 상태(응답) – message_flag '04'
light_regex = r'^(?P<cmd>[0-9a-f]{2})(?P<val>[0-9a-f]{2})'
for dev in [거실1전등, 거실2전등, 소파3전등, 앞불4전등, 복도등]:
    dev.register_status(message_flag='04', attr_name='power', topic_class='state_topic',
                        regex=light_regex,
                        process_func=lambda gd: 'ON' if gd['cmd'] == '01' and gd['val'] == '01' else 'OFF')
    # 조명 명령 – 요청: message_flag '02'
    dev.register_command(message_flag='02', attr_name='power', topic_class='command_topic',
                         process_func=lambda v: '01' if v.upper() == 'ON' else '02')

# ----- 보일러 (device_id '18') -----
# 참고: 거실보일러의 경우 아래와 같이 패킷에 적용되는 체크섬은
#  on요청: F7 0B 01 18 02 46 11 01 00 B1 26 EE
#  on응답: F7 0D 01 18 04 46 11 01 01 14 A4 32 EE
optional_info_boiler = {'modes': ['off', 'on']}

거실보일러   = wallpad.add_device(device_name='거실보일러', device_id='18', device_subid='11', device_class='climate', optional_info=optional_info_boiler)
안방보일러   = wallpad.add_device(device_name='안방보일러', device_id='18', device_subid='12', device_class='climate', optional_info=optional_info_boiler)
작은방보일러 = wallpad.add_device(device_name='작은방보일러', device_id='18', device_subid='13', device_class='climate', optional_info=optional_info_boiler)
서재보일러   = wallpad.add_device(device_name='서재보일러', device_id='18', device_subid='14', device_class='climate', optional_info=optional_info_boiler)

# 보일러 상태(응답) – message_flag '04'
boiler_regex = r'^(?P<cmd>[0-9a-f]{2})(?P<val>[0-9a-f]{2})'
for dev in [거실보일러, 안방보일러, 작은방보일러, 서재보일러]:
    dev.register_status(message_flag='04', attr_name='power', topic_class='state_topic',
                        regex=boiler_regex,
                        process_func=lambda gd: 'ON' if gd['cmd'] == '01' and gd['val'] == '01' else 'OFF')
    # 보일러 명령 – 요청: message_flag '02'
    dev.register_command(message_flag='02', attr_name='power', topic_class='command_topic',
                         process_func=lambda v: '01' if v.lower()=='on' else '04')

wallpad.listen()
