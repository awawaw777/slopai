"""Illustrative catalog. Replace prices and stock before accepting real orders."""
CATEGORIES = {'cpu': 'Процессор', 'gpu': 'Видеокарта', 'board': 'Материнская плата', 'ram': 'Оперативная память', 'ssd': 'Накопитель', 'cooler': 'Охлаждение', 'psu': 'Блок питания', 'case': 'Корпус'}
PARTS = {
 'cpu': [dict(id='r5600', name='AMD Ryzen 5 5600', detail='6 ядер · 12 потоков · AM4', price=10900, socket='AM4', watts=65), dict(id='r7600', name='AMD Ryzen 5 7600', detail='6 ядер · 12 потоков · AM5', price=18900, socket='AM5', watts=65), dict(id='r7700', name='AMD Ryzen 7 7700', detail='8 ядер · 16 потоков · AM5', price=27900, socket='AM5', watts=65)],
 'gpu': [dict(id='rtx4060', name='GeForce RTX 4060', detail='8 ГБ GDDR6 · 1080p', price=32900, watts=115, length=250), dict(id='rtx4070s', name='GeForce RTX 4070 SUPER', detail='12 ГБ GDDR6X · 1440p', price=67900, watts=220, length=300), dict(id='rtx4080s', name='GeForce RTX 4080 SUPER', detail='16 ГБ GDDR6X · 4K', price=119900, watts=320, length=340)],
 'board': [dict(id='b550', name='B550M / AM4', detail='micro-ATX · DDR4 · M.2', price=9900, socket='AM4', memory='DDR4'), dict(id='b650', name='B650 / AM5', detail='ATX · DDR5 · M.2', price=15900, socket='AM5', memory='DDR5')],
 'ram': [dict(id='d4-16', name='16 ГБ DDR4', detail='2 × 8 ГБ · 3200 МГц', price=3900, memory='DDR4'), dict(id='d4-32', name='32 ГБ DDR4', detail='2 × 16 ГБ · 3200 МГц', price=6900, memory='DDR4'), dict(id='d5-32', name='32 ГБ DDR5', detail='2 × 16 ГБ · 6000 МГц', price=10900, memory='DDR5'), dict(id='d5-64', name='64 ГБ DDR5', detail='2 × 32 ГБ · 6000 МГц', price=19900, memory='DDR5')],
 'ssd': [dict(id='ssd1', name='SSD NVMe 1 ТБ', detail='PCIe 4.0 · M.2 2280', price=6900), dict(id='ssd2', name='SSD NVMe 2 ТБ', detail='PCIe 4.0 · M.2 2280', price=11900)],
 'cooler': [dict(id='air', name='Башенное охлаждение', detail='120 мм · AM4 / AM5 · до 150 Вт', price=2900, capacity=150, height=155), dict(id='airpro', name='Двухбашенное охлаждение', detail='2 × 120 мм · AM4 / AM5 · до 220 Вт', price=5900, capacity=220, height=160)],
 'psu': [dict(id='psu550', name='550 Вт Bronze', detail='80 PLUS Bronze', price=4900, capacity=550), dict(id='psu750', name='750 Вт Gold', detail='80 PLUS Gold · модульный', price=8900, capacity=750), dict(id='psu850', name='850 Вт Gold', detail='80 PLUS Gold · модульный', price=11900, capacity=850)],
 'case': [dict(id='compact', name='SlopAI Compact', detail='ATX · GPU до 320 мм · кулер до 160 мм', price=5900, gpu_limit=320, cooler_limit=160), dict(id='airflow', name='SlopAI Airflow', detail='ATX · GPU до 360 мм · кулер до 170 мм', price=8900, gpu_limit=360, cooler_limit=170)]
}
PRESETS = [
 dict(id='start', name='START', tagline='Твоя точка входа', category='Для учёбы и игр', label='1080p', cpu='r5600', gpu='rtx4060', board='b550', ram='d4-16', ssd='ssd1', cooler='air', psu='psu550', case='compact'),
 dict(id='play', name='PLAY', tagline='Больше кадров. Больше игры.', category='Для игр', label='1440p', cpu='r7600', gpu='rtx4070s', board='b650', ram='d5-32', ssd='ssd1', cooler='air', psu='psu750', case='airflow'),
 dict(id='pro', name='PRO', tagline='Для больших проектов', category='Для работы и игр', label='4K', cpu='r7700', gpu='rtx4080s', board='b650', ram='d5-64', ssd='ssd2', cooler='airpro', psu='psu850', case='airflow')
]

# Дополнительные варианты на основе той же проверенной платформы.
PRESETS.extend([
    dict(PRESETS[0], id='start-plus', name='START PLUS', tagline='Больше места для твоих игр', ram='d4-32', ssd='ssd2'),
    dict(PRESETS[1], id='studio', name='STUDIO', tagline='Многозадачность без компромиссов', category='Для работы и игр', cpu='r7700', ram='d5-64', ssd='ssd2', cooler='airpro'),
    dict(PRESETS[2], id='ultra', name='ULTRA', tagline='Большой экран. Большие планы.', category='Для игр', ram='d5-32')
])

def resolve(selection):
    result = {}
    for category, options in PARTS.items():
        part = next((p for p in options if p['id'] == selection.get(category)), None)
        if not part:
            raise ValueError('Выберите комплектующие во всех категориях.')
        result[category] = part
    return result

def compatibility(parts):
    errors = []
    if parts['cpu']['socket'] != parts['board']['socket']:
        errors.append('Сокет процессора и материнской платы должен совпадать.')
    if parts['ram']['memory'] != parts['board']['memory']:
        errors.append('Тип памяти не подходит к материнской плате.')
    required = int((parts['cpu']['watts'] + parts['gpu']['watts'] + 80) * 1.3)
    if parts['psu']['capacity'] < required:
        errors.append(f'Нужен блок питания мощностью не менее {required} Вт.')
    if parts['gpu']['length'] > parts['case']['gpu_limit']:
        errors.append('Видеокарта слишком длинная для выбранного корпуса.')
    if parts['cooler']['height'] > parts['case']['cooler_limit']:
        errors.append('Охлаждение не помещается в корпус.')
    if parts['cooler']['capacity'] < parts['cpu']['watts']:
        errors.append('Недостаточная мощность охлаждения.')
    return errors, required

def price(parts):
    return sum(p['price'] for p in parts.values())
