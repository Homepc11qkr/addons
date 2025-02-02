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
        # 최신 API 사용을 위해 protocol을 명시합니다.
        self.mqtt_client = mqtt.Client(protocol=mqtt.MQTTv311)
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
        # 연결 해제 시 예외를 발생시키지 않고 로그를 출력하며 재연결 시도
        print("MQTT 연결이 해제되었습니다. rc:", rc)
        # 재연결을 시도합니다.
        while True:
            try:
                client.reconnect()
                print("재연결 성공")
                break
            except Exception as e:
                print("재연결 실패:", e)
                time.sleep(5)

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

# --------------------------------------------------
# 참고: 보일러 관련 추가 채널(예, 7, 8번)의 예제도 유사하게 등록 가능함.
# 예)
#  거실보일러 7 요청: F7 0B 01 18 02 45 11 07 00 B4 EE
#  거실보일러 7 응답: F7 0D 01 18 04 45 11 07 01 14 07 A6 EE
#  거실보일러 8 요청: F7 0B 01 18 02 45 11 08 00 BB EE
#  거실보일러 8 응답: F7 0D 01 18 04 45 11 08 01 14 08 A6 EE
# --------------------------------------------------

# ============================================================
# 프로그램 시작
# ============================================================
wallpad.listen()
# 2025_0202
