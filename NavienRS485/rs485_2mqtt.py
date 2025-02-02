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
