import json
import os
import queue
import threading

from zhconv import convert

text = "要将Python字符串中的中文转换为繁体字"
trad_text = convert(text, 'zh-tw')
dict = {'美国宇航局': '美利坚合众国', '美国购物': '美利坚合众国', 'FOX 体育新闻': '体育',
        '美国历史': '美利坚合众国', '红牛运动': '体育', '美国1': '美利坚合众国',
        '美国之音': '美利坚合众国', 'redbull tv': '体育', '普洱科教': '电视台', '州科教': '电视台',
        '经济科教': '电视台', '长城精品': '纪录片',
        '绵阳科技': '电视台', ' Fox Sports Racing': '体育', '2016 EURO 2': '体育', 'A BOLA TV 1 PT': '体育',
        'A1 Sports': '体育', 'ASTRO Arena 2': '体育',
        'Abu Dhabi Sport 2 UAE': '体育', 'Abu Dhabi Sports 1': '体育', 'Abu Dhabi Sports 2': '体育',
        'Abu Dhabi Sports 5': '体育', 'All Sports': '体育', 'All Sports TV': '体育', 'Arryadia TV': '体育',
        'Astro Supersports 1': '体育', '澳視澳門': '港澳台', '澳視综艺': '港澳台', '澳視葡文': '港澳台',
        '澳門MACAU': '港澳台', '澳門蓮花': '港澳台', '澳門衛視': '港澳台', '澳門資訊': '港澳台',
        '115新天地民俗臺': '港澳台', 'AXN': '港澳台', 'CHANNEL [V]': '港澳台', 'CMusic': '港澳台',
        'DISCOVERY Channel': '港澳台', 'DISCOVERY HD WORLD': '港澳台', 'EYE TV戲劇': '港澳台',
        'EYE TV旅遊': '港澳台', 'Eleven Sports1': '港澳台', 'Eleven Sports2': '港澳台',
        'Food Network(TW)': '港澳台', 'Hollywood': '港澳台', 'LINE TV 網路電視': '港澳台',
        'Love Nature': '港澳台', 'MOMO綜合臺': '港澳台', 'MOMO購物1臺': '港澳台', 'MOMO購物2臺': '港澳台',
        'Next TV': '港澳台', 'PET CLUB TV': '港澳台', 'ROCK Entertainment': '港澳台', 'ROCK Extreme': '港澳台',
        'TVBS FHD': '港澳台', 'TVBS HD': '港澳台', 'Taiwan Plus': '港澳台', 'UDN TV': '港澳台', 'Z': '港澳台',
        '三立INEWS FHD': '港澳台', '三立INEWS HD': '港澳台', '三立國際': '港澳台', '三立戲劇': '港澳台',
        '三立新聞': '港澳台', '三立綜合': '港澳台', '三立臺灣台': '港澳台', '三立都會': '港澳台',
        '中天亞洲': '港澳台', '中天新聞': '港澳台', '中視HD': '港澳台', '中視新聞': '港澳台',
        '中視新聞臺': '港澳台', '中視經典': '港澳台', '亞洲旅遊臺': '港澳台', '人間衛視': '港澳台',
        '信吉電視': '港澳台', '信大電視': '港澳台', '八大綜合': '港澳台', '創世電視': '港澳台',
        '博斯網球': '港澳台', '博斯運動': '港澳台', '博斯高球': '港澳台', '博斯魅力': '港澳台',
        '唯心電視': '港澳台', '國家地理頻道': '港澳台', '國會頻道1': '港澳台', '大愛': '港澳台',
        '大愛2': '港澳台', '大立電視臺': '港澳台', '好萊塢電影': '港澳台', '好訊息': '港澳台',
        '好訊息 2': '港澳台', '寰宇新聞': '港澳台', '星衛HD電影': '港澳台', '東森幼幼': '港澳台',
        '東森戲劇': '港澳台', '東森新聞': '港澳台', '東森新聞臺': '港澳台', '東森洋片': '港澳台',
        '東森綜合': '港澳台', '東森美洲': '港澳台', '東森衛視': '港澳台', '東森財經': '港澳台',
        '東森財經新聞': '港澳台', '東森超視': '港澳台', '東森電影': '港澳台', '東風37': '港澳台',
        '民視': '港澳台', '民視新聞': '港澳台', '民視新聞 HD': '港澳台', '民視臺灣台': '港澳台',
        '生命電視': '港澳台', '番薯電視': '港澳台', '經典電影臺': '港澳台', '緯來日本': '港澳台',
        '緯來綜合': '港澳台', '緯來育樂': '港澳台', '美亞電影臺': '港澳台', '美食星球': '港澳台',
        '臺視新聞': '港澳台', '臺視新聞臺': '港澳台', '臺視綜合': '港澳台', '華視': '港澳台',
        '華視新聞': '港澳台', '華視新聞資訊': '港澳台', '衛視電影': '港澳台', '鏡新聞': '港澳台',
        '靖天卡通': '港澳台', '靖天國際': '港澳台', '龍祥電影': '港澳台', '龍華偶像': '港澳台',
        '龍華戲劇': '港澳台', '龍華洋片': '港澳台',
        'Astro Supersports 2': '体育', 'Astro Supersports 3': '体育', 'Astro Supersports 4': '体育',
        'Astro Supersports 5': '体育', 'BAHRAIN_SPORTS': '体育', 'BEIN SPORT 1 HD ': '体育',
        'BEIN SPORT 2 HD ': '体育', 'BEIN SPORT 5 HD ': '体育', 'BEIN SPORT Ar10': '体育',
        'BESTV超級體育': '体育', 'BT Sport 1': '体育', 'BT Sport 2': '体育', 'BT Sport 3': '体育',
        'BT Sport 4': '体育', 'BT Sport ESPN': '体育', 'BT Sports 2 HD': '体育', 'Bally Sports': '体育',
        'Band Sports': '体育', 'BeIN Sports 1': '体育', 'BeIN Sports 2': '体育', 'BeIN Sports3 EN': '体育',
        'Bein Sport 3 France': '体育', 'Bein Sport HD 1 Qatar (Arabic)': '体育',
        'Bein Sports 3 France (English)': '体育', 'Bein Sports 5 France (English)': '体育',
        'Bein Sports HD': '体育', 'Bein Sports HD 1 France': '体育', 'Brodilo TV HD': '体育', 'CCTV16': '体育',
        'CCTV5': '体育', 'CCTV5+': '体育',
        'CCTV央視檯球': '体育', 'CCTV風雲足球': '体育', 'CCTV高爾夫網球': '体育',
        'Canal 4 (El Salvador)': '体育', 'Canal Esport3': '体育', 'Claro Sports': '体育', 'DD Sports': '体育',
        'Diema Sport 1-2': '体育', 'ATV A1臺': '港澳台', 'ATV WORLD': '港澳台', 'Channel V HD': '港澳台',
        'Discovery Kids': '港澳台', 'HOY TV': '港澳台', 'ITV Granada': '港澳台', 'J2': '港澳台',
        'NOW Sports': '港澳台', 'Now Sports 2': '港澳台', 'Now Sports 3': '港澳台', 'Now Sports 5': '港澳台',
        'Now Sports 6': '港澳台', 'Now Sports 7': '港澳台', 'Now TV': '港澳台', 'RTHK31': '港澳台',
        'RTHK32': '港澳台', 'RTHK33': '港澳台', 'RTHK34': '港澳台', 'Sports Plus 1': '港澳台',
        'Star Sports2': '港澳台', 'TVB E': '港澳台', 'TVB J2': '港澳台', 'TVB J2生活台': '港澳台',
        'TVB 翡翠臺': '港澳台', 'TVB1(US)': '港澳台', 'TVB娛樂新聞': '港澳台', 'TVB新聞': '港澳台',
        'TVB星河': '港澳台', 'TVB無線財經': '港澳台', 'TVB經典': '港澳台', 'Viu TV': '港澳台',
        '天威TVG': '港澳台', '天映經典': '港澳台', '天映頻道': '港澳台', '幸運88臺': '港澳台',
        '有線18臺': '港澳台', '有線新聞': '港澳台', '有線直播新聞': '港澳台', '有線財經資訊臺': '港澳台',
        '港臺電影': '港澳台', '無線新聞臺': '港澳台', '無線財經臺': '港澳台', '熱血時報': '港澳台',
        '翡翠臺': '港澳台', '耀才財經臺': '港澳台', '財經資訊': '港澳台', '香港國際財經臺': '港澳台',
        '香港衛視': '港澳台', '香港開電視': '港澳台', '鳳凰Show': '港澳台', '鳳凰資訊HD': '港澳台',
        '鳳凰電影': '港澳台', '鳳凰香港': '港澳台', '麵包臺': '港澳台',
        'Dubai Racing 2 TV': '体育', 'Dubai Racing TV': '体育', 'Dubai Sport 1': '体育', 'ESPN 3': '体育',
        'ESPN NEWS': '体育',
        'ESPN U': '体育', 'EURO SPORT 1 HD': '体育', 'EUROSPORT 1 Portugal': '体育', 'EuroSport 2 HD UK': '体育',
        'EuroSport Deutschland': '体育', 'Eurosport 2': '体育', 'Eurosport2 HD UK': '体育',
        'Eurosports 1 HD UK': '体育', 'FOX Sports 2': '体育', 'FOX Sports 3': '体育', 'FS1': '体育',
        'Fight Box HD': '体育', 'Fight Sports': '体育',
        'FightBox TV': '体育', 'Fox Sports 1': '体育',
        'Fox Sports 1 USA': '体育', 'Fox Sports Turk': '体育', 'GOLF': '体育', 'Goan_TV': '体育',
        'Golf Channel': '体育', 'HTV Thể thao': '体育', 'HUB Sports2': '体育',
        'HUBPREMIER EFL 2': '体育', 'IB Sports TV': '体育', 'ITV': '体育', 'ITV 4 UK': '体育',
        'J SPORTS 1': '体育', 'J SPORTS 2': '体育', 'J SPORTS 4': '体育', 'KBSN LIFE': '体育',
        'KSA Sports': '体育', 'Kompas TV': '体育',
        'Equipe': '体育', 'Liga De Campeones 2': '体育', 'MBC Sport 1': '体育', 'MCOT HD': '体育',
        'MLB': '体育', 'MOTORVISION HD': '体育', 'MUTV': '体育', 'Marca TV': '体育',
        'Meridiano Televisión': '体育', 'Milan Channel': '体育', 'Mitele Deportes': '体育',
        'Motorsz TV': '体育', 'Movistar Deportes': '体育', 'N SPORT+': '体育', 'NBA HD': '体育',
        'NBA Premium': '体育', 'NBA TV': '体育', 'NBC Sport': '体育', 'NBCSN': '体育', 'NBT HD': '体育',
        'NESN': '体育', 'NEWTV武搏世界': '体育', 'NEWTV精品體育': '体育', 'NEWTV超級體育': '体育',
        'NFL': '体育', 'NFL REDZONE': '体育', 'NOVA SPORT': '体育', 'NPO Sport': '体育',
        'NTV CAMBODIA': '体育', 'Nautical Channel Russia': '体育', 'ORANGE SPORT': '体育',
        'OSN Fight HD UAE': '体育', 'PFC O Canal Do Futebol': '体育',
        'PPV 1 (LIVE EVENT)': '体育', 'PPV 3': '体育', 'PX TV': '体育', 'Pac12': '体育',
        'Persiana Game & Tech': '体育', 'Pocker Central': '体育', 'Polsat Sport PL': '体育',
        'Premier Sport': '体育', 'Premier Sports': '体育', 'Premium Calcio Italia': '体育',
        'Pro Wrestling Channel': '体育', 'RDS 2 HD': '体育', 'RMC Sport France': '体育',
        'RTL Nitro Deutschland': '体育', 'RTSH Sport HD': '体育', 'Rai Sport 2 SD': '体育',
        'Real Madrid TV': '体育', 'Red Bull TV': '体育', 'Russian Extreme': '体育', 'S SPORT TV': '体育',
        'SBS Sports': '体育', 'SCTV15 SPORT': '体育', 'SETANTA SPORTS+': '体育', 'SKY Bundesliga 1': '体育',
        'SKY Sports Arena': '体育', 'SKY Sports Football': '体育', 'SKY Sports MIX': '体育',
        'SKYNET SPORTS HD': '体育', 'SPORT 5 LIVE': '体育', 'SPORT 5+ LIVE': '体育', 'SPORT MAX': '体育',
        'SPORT TV 3 PT': '体育', 'SPOTV 1': '体育', 'SPOTV2': '体育',
        'STAR SPORTS SELECT 1': '体育', 'Samurai Fighting TV': '体育', 'Setanta': '体育',
        'Setanta Sports HD': '体育', 'Sky Calcio': '体育', 'Sky Sport 24 HD Italia': '体育',
        'Sky Sport F1 HD Italia': '体育', 'Sky Sports Action': '体育', 'Sky Sports F1': '体育',
        'Sky Sports Golf': '体育', 'Sky Sports Main Event': '体育', 'Sky Sports NFL': '体育',
        'Sky Sports News HQ': '体育', 'Sky Sports Premier League': '体育', 'Sky Sports Racing': '体育',
        'Sony Ten2': '体育', 'Sony Ten3': '体育', 'SporTV 1': '体育', 'Sport - San Marino RTV': '体育',
        'Sport 1': '体育', 'Sport 1 HD': '体育', 'Sport 1 Select HD Netherlands': '体育',
        'Sport Italia': '体育', 'Sport Klub 2 HD Srbija': '体育', 'Sport Klub 2 Srbija': '体育',
        'Sport Klub 3 HD Srbija': '体育', 'Sport Plus': '体育', 'Sport TV 1': '体育', 'Sport TV 2': '体育',
        'Sport TV 3': '体育', 'Sport TV 4': '体育', 'Sport TV1': '体育', 'Sport TV3': '体育',
        'Sporting TV': '体育', 'Sports Network': '体育', 'SportsNet 1': '体育',
        'Sportsnet West': '体育', 'Stadium4 Thai': '体育', 'Star Sport 1': '体育', 'Sukan RTM': '体育',
        'Super Sport 3 HD': '体育', 'SuperSport Cricket': '体育', 'SuperTennis TV': '体育',
        'Supersport Football': '体育', 'TDP Teledeporte': '体育', 'TF1 HD': '体育', 'TFX': '体育',
        'TIDE SPORTS': '体育', 'TSN 1': '体育', 'TSN 2': '体育', 'TSN 3': '体育', 'TSN 4': '体育',
        'TV 2 Sport': '体育', 'TV 2 Sportskanalen': '体育', 'TV Globo': '体育', 'TV TOUR': '体育',
        'TV Urbana': '体育', 'TVA SPORT': '体育', 'TVCG 2': '体育', 'TVMax': '体育',
        'TVU Esporte Brasil': '体育', 'Tele Rebelde': '体育', 'Telemetro canal 13, Panamá': '体育',
        'Telemundo': '体育', 'Telemundo 48 El Paso': '体育', 'Telenord': '体育', 'Tempo TV': '体育',
        'Tennis': '体育', 'Tivibu Spor Türkiye': '体育', 'Trace Sport Stars': '体育', 'Trace Sports': '体育',
        'Tring Sport 2 Albania': '体育', 'Tsn Livigno': '体育', 'Tv Luna Sport': '体育', 'TyC Sports': '体育',
        'Türkmen Sport': '体育', 'UFC TV': '体育', 'Unbeaten Esports': '体育', 'Univisión TDN Mexico': '体育',
        'Usee sports': '体育', 'ViaSat Sport Россия': '体育', 'Viasat Motor Sweden': '体育',
        'Viasat Sport HD Sweden': '体育', 'WWE HD': '体育', 'WWE Network': '体育',
        'Win Sports': '体育', 'World Fishing Network': '体育', 'XPER TV Costa Rica': '体育',
        'XSport Ukraine': '体育', 'Yas Sports': '体育', 'a Spor TUR': '体育', 'adsport 1': '体育',
        'adsport 2': '体育', 'beIN SPORTS France': '体育', 'beIN Sports 2 ID': '体育',
        'beIN Sports 3 ID': '体育', 'beIN Sports MENA': '体育', 'iDMAN TV Türkiye': '体育',
        'İdman Azərbaycan TV': '体育', 'МАТЧ! БОЕЦ': '体育', 'Матч ТВ': '体育', 'Матч!': '体育',
        'НТВ Плюс Теннис Россия': '体育', 'Перший Avtomobilniy': '体育', 'Спорт Россия': '体育',
        'Телеканал Старт': '体育', 'Телеканал Футбол 1': '体育', '五星體育': '体育', '先鋒乒羽': '体育',
        '勁爆體育': '体育', '北京冬奥纪实': '体育', '北京體育': '体育', '北京體育休閒': '体育',
        '噠啵賽事': '体育',
        '四海釣魚': '体育', '天元圍棋': '体育', '天津體育': '体育', '山東體育': '体育', '廣東體育': '体育',
        '快樂垂釣': '体育', '武漢文體': '体育', '武術世界': '体育', '江蘇體育休閒': '体育',
        '洛陽新聞綜合': '体育', '精彩體育': '体育', '遊戲風雲': '体育', '運動健身': '体育',
        '陝西體育休閒': '体育', '電競天堂': '体育', '體育賽事': '体育', '高爾夫': '体育', '魅力足球': '体育',
        'FOXNews': '美利坚合众国', 'Ion Plus': '美利坚合众国', 'ION Plus': '美利坚合众国',
        '美国中文': '美利坚合众国', '美国狗狗宠物': '美利坚合众国', 'BlazeTV': '美利坚合众国',
        'Seattle Channel': '美利坚合众国', '美国新闻': '美利坚合众国', 'CBS News': '美利坚合众国',
        'TBS': '美利坚合众国', 'NBC': '美利坚合众国', 'Hallmark Movies': '美利坚合众国',
        'Disney XD': '美利坚合众国', 'AMC US': '美利坚合众国',
        'HGTV': '美利坚合众国', 'tru TV': '美利坚合众国', 'Fox 5 WNYW': '美利坚合众国',
        'ABC HD': '美利坚合众国', 'My9NJ': '美利坚合众国', 'Live Well Network': '美利坚合众国',
        'Gulli': '美利坚合众国', 'Tiji TV': '美利坚合众国', 'WPIX-TV': '美利坚合众国',
        'MOTORTREND': '美利坚合众国', 'BBC America': '美利坚合众国', 'THIRTEEN': '美利坚合众国',
        'WLIW21': '美利坚合众国', 'NJTV': '美利坚合众国', 'MeTV': '美利坚合众国', 'SBN': '美利坚合众国',
        'WMBC Digital Television': '美利坚合众国', 'Univision': '美利坚合众国', 'nba': '美利坚合众国',
        'NBA': '美利坚合众国', 'fox news': '美利坚合众国', 'FOX News': '美利坚合众国',
        '.sci-fi': '美利坚合众国', 'UniMÁS': '美利坚合众国', 'Cartoons_90': '美利坚合众国',
        'Cartoons Short': '美利坚合众国', 'Cartoons Big': '美利坚合众国', 'CineMan': '美利坚合众国',
        'USA': '美利坚合众国', 'BCU Кинозал Premiere': '美利坚合众国', 'TNT': '美利坚合众国',
        'NBC NEWS': '美利坚合众国', 'SKY SPORT': '体育', 'Auto Motor Sport': '体育',
        'sky sport': '体育', 'sky Sport': '体育', 'BT SPORT': '体育', 'sportv': '体育',
        'fight sport': '体育', 'Sportitalia': '体育', 'sportitalia': '体育', 'elta sport': '体育',
        'Sport 5': '体育', 'claro sport': '体育', 'xsport': '体育', 'sporting': '体育', 'TV3 sport': '体育',
        'Trace Sport': '体育', 'SPORT 1': '体育', 'sport 3': '体育', 'sport 4k': '体育',
        'edgesport': '体育', 'sport club': '体育', 'sport tv': '体育', 'j sport': '体育',
        'viasat sport': '体育', 'sport 5': '体育',
        'QAZsport_live': '体育', 'SPORT 5': '体育', 'SPORT 2': '体育', 'Alfa Sport': '体育',
        'tring sport': '体育', 'wwe': '体育', 'WWE': '体育',
        'Sportv': '体育', 'diema sport': '体育', 'Edge Sport': '体育', 'supersport': '体育', 'sport ru': '体育',
        'Sport+': '体育', 'Esport3': '体育', 'Sport En France': '体育', 'sport en': '体育',
        'sports': '体育', 'Pluto TV SPORT': '体育', 'NBC News': '体育', 'ssc sport': '体育', 'SporTV': '体育',
        'bein sport': '体育', 'Sports': '体育', 'SPORT TV': '体育',
        'FR_RMC_Sport': '体育', 'EDGEsport': '体育', 'Box Nation': '体育', 'Brodilo TV': '体育',
        'CBC Sport': '体育', 'cbc Sport': '体育', '檯球': '体育', '央视台球': '体育', '风云足球': '体育',
        '風雲足球': '体育', '高爾夫網球': '体育', '高尔夫网球': '体育', 'CDN Deportes': '体育',
        'CDO PREMIUM SANTIAGO CHILE LATAM': '体育',
        'SPORTS': '体育', 'k+ sport': '体育', 'digi sport': '体育', 'Eurosport': '体育', 'Sport 3': '体育',
        'cdo premium': '体育', 'CSI Web Tv': '体育', 'Campo Televisión': '体育', 'Canal 4': '体育',
        'canal 4': '体育', 'Canal+ Sport': '体育', 'canal+ sport': '体育', 'Chelsea TV': '体育',
        'chelsea tv': '体育', 'DAZN F1': '体育', 'dazn f1': '体育', 'DIGISPORT': '体育', 'DMC Sport': '体育',
        'NFL NETWORK': '美利坚合众国', 'WWE NETWORK': '体育', 'A&E': '美利坚合众国', 'Dazn 1': '体育',
        'AMC': '美利坚合众国', 'BBC AMERICA': '美利坚合众国', 'BET': '美利坚合众国', 'dazn 1': '体育',
        'BRAVO': '美利坚合众国', 'USA NETWORK': '美利坚合众国', 'CNBC': '美利坚合众国', 'dazn 01': '体育',
        'NHL Network': '美利坚合众国', '5USA': '美利坚合众国', 'CBS SPORTS': '体育', 'dazn 2': '体育',
        'FOX SPORTS': '体育', 'MSG US': '美利坚合众国', 'MSG 2 US': '美利坚合众国', 'dazn 3': '体育',
        'dazn 4': '体育', 'deportv': '体育', 'DeporTV': '体育', 'Diema Sport': '体育', 'Dubai Racing': '体育',
        'dubai racing': '体育', 'Dubai Sport': '体育', 'dubai sport': '体育', 'EDGE Sport': '体育',
        'edge sport': '体育', 'EURO SPORT': '体育', 'edge sportᴴᴰ': '体育', 'ESL Gaming tv': '体育',
        'gaming tv': '体育', 'ESPN': '体育', 'espn': '体育', 'eurosport': '体育', 'EUROSPORT': '体育',
        'Equipe 21': '体育', 'equipe 21': '体育', 'Esports Max': '体育', 'esports max': '体育',
        'EuroSport': '体育', 'FOX Deportes': '体育', 'fox deportes': '体育', 'FOX SP506': '体育',
        'FOX 5 Atlanta GA': '体育', 'WAGA-TV': '体育', 'fox sport': '体育', 'Fast&FunBox': '体育',
        'funbox': '体育', 'fast&fun box': '体育', 'Fenerbahce TV': '体育', 'fenerbahçe tv': '体育',
        'Ion Television': '美利坚合众国', 'NYCTV Life': '美利坚合众国', 'TENNIS HD': '美利坚合众国',
        'CINEMAXX MORE MAXX': '美利坚合众国', 'CINEMAX THRILLERMAX': '美利坚合众国',
        'fight box': '体育', 'Fight Box': '体育', 'Fight Channel': '体育', 'channel fight': '体育',
        'fightbox': '体育', 'FightBox': '体育', 'Football Thai': '体育', 'Football UK': '体育',
        'CINEMAX OUTER MAX': '美利坚合众国', 'CINEMAX MOVIEMAX': '美利坚合众国', 'on football': '体育',
        'CINEMAX ACTION MAX': '美利坚合众国', 'MTV Classic': '美利坚合众国', 'football focus': '体育',
        'football fhd': '体育', 'gol tv': '体育', 'GOLTV': '体育', 'goltv': '体育', 'Game Show Network': '体育',
        'Gameplay Roblox': '体育', 'gameplay: roblox': '体育', 'roblox': '体育', 'Gamer.tv': '体育',
        'Espn News': '美利坚合众国', 'ESPN 2': '美利坚合众国', 'ESPN USA': '美利坚合众国',
        'Discovery Channel': '美利坚合众国', 'MAVTV': '美利坚合众国', '布兰奇电视': '美利坚合众国',
        '美国l': '美利坚合众国', '美国中央台': '美利坚合众国', 'IN: Harvest TV USA': '美利坚合众国',
        'LeSEA Broadcasting Network': '美利坚合众国', 'US: USA Network': '美利坚合众国',
        'CBS New York': '美利坚合众国', 'ABC News': '美利坚合众国', 'AFG: ATN USA': '美利坚合众国',
        'usa fight network': '美利坚合众国', 'E! Entertaiment USA': '美利坚合众国',
        'USA Today': '美利坚合众国', 'usa espn': '美利坚合众国', 'UK: 5 USA': '美利坚合众国',
        'CMC-USA': '美利坚合众国', 'usa disney': '美利坚合众国', 'usa network': '美利坚合众国',
        'usa ufc': '美利坚合众国', 'usa wwe': '体育', 'usa mtv': '美利坚合众国',
        'usa crime': '美利坚合众国', 'usa cnbc': '美利坚合众国', 'GoUSA TV': '美利坚合众国',
        'Harvest TV USA': '美利坚合众国', 'jltv usa': '美利坚合众国', 'Best Movies HD (USA)': '美利坚合众国',
        'usa news': '美利坚合众国', 'Go USA': '美利坚合众国', 'usa american heroes': '美利坚合众国',
        'usa tcm': '美利坚合众国', 'lesea broadcasting network (usa)': '美利坚合众国',
        'usa c-span': '美利坚合众国', 'usa hbo': '美利坚合众国', 'cnn usa': '美利坚合众国',
        'CNN': '美利坚合众国', 'usa': '美利坚合众国', 'american': '美利坚合众国', 'Gunma TV': '日本台',
        'American': '美利坚合众国', 'cnn': '美利坚合众国', 'CNNj': '日本台', 'FUJI TV': '日本台',
        'fuji tv': '日本台', 'Golf Network': '体育', 'golazo network': '体育',
        'TOKYO MX': '日本台', 'Tokyo MX': '日本台', 'tokyo mx': '日本台', 'Weather News': '日本台',
        'weathernews': '日本台', '香港電視娛樂': '港澳台',
        'WeatherNews': '日本台', 'hoy tv': '港澳台', 'NHK': '日本台', 'TV Tokyo': '日本台', 'Star 1': '日本台',
        'Star 2': '日本台', 'Nippon TV': '日本台', 'MBS': '日本台', 'Animax': '日本台', 'QVC Japan': '日本台'
    , 'ANIMAX': '日本台', 'animax': '日本台', 'nhk': '日本台', 'qvc - japan': '日本台',
        'qvc japan': '日本台', '朝日': '日本台', 'aniplus': '日本台', 'JSTV': '日本台', 'directv sport': '体育',
        'WeatherSpy': '日本台', 'dTV(Japan)': '日本台', 'A BOLA TV': '体育', 'A-sport': '体育',
        'astro supersport': '体育', 'Automoto': '体育', 'BEIN SPORT': '体育', 'bein sports': '体育',
        'ziggo sport': '体育', 'sharjjah sport': '体育', 'mysports 1': '体育', 'AS TV Spain': '体育',
        'Arena Sport': '体育', 'arena sport': '体育', 'Argentina - TyC': '体育', 'Astro Supersports': '体育',
        'NHK BS': '日本台', 'nhk world': '国际', 'STAR CHANNEL': '日本台', 'star channe': '日本台',
        'Samurai Fighting': '日本台', 'samurai x': '日本台', 'euro star': '日本台', 'star tv': '日本台',
        'tv asahi': '日本台', 'U-NEXT': '日本台', 'Degrassi The Next Generation': '日本台',
        'tv tokyo': '日本台', 'Aniplus': '日本台', 'BS TBS': '日本台', 'Jupiter Shop Channel': '日本台',
        'KIDS STATION': '日本台', 'Kansai TV': '日本台', 'kanshi tv': '日本台', 'Lala TV': '日本台',
        'lana tv': '日本台', 'MBS JAPAN': '日本台', 'Mondo TV': '日本台', 'MONDO TV': '日本台',
        'Fuji TV': '日本台', 'TV Asahi': '日本台', 'テレビ東京': '日本台', 'BS Fuji': '日本台',
        'bs-tbs': '日本台', 'BS Asahi': '日本台', 'BS Tokyo': '日本台', 'WOWOW Prime': '日本台',
        'WOWOWO 电影': '日本台', '云游日本': '日本台', '日本女子摔角': '日本台', 'TBS NEWS': '日本台',
        '日本テレビ': '日本台', 'WOWOWライブ': '日本台', 'WOWOWプライム': '日本台', 'J Sports': '体育',
        '人间卫视': '港澳台', 'Animal': '自然', '日本购物': '日本台', 'Disney Channel Japan': '日本台',
        'JAPAN3': '日本台', 'JAPAN5': '日本台', 'JAPAN6': '日本台', 'JAPAN7': '日本台', 'JAPAN8': '日本台',
        'JAPAN9': '日本台', '日本News24': '日本台', '日本映画': '日本台', 'GSTV': '日本台',
        'WOWOWシネマ': '日本台', 'BS12 TwellV': '日本台', 'BS朝日': '日本台', '超級體育': '体育',
        '超级体育': '体育',
        'BT Sport': '体育', 'bt sport': '体育',
        'スターチャンネル': '日本台', 'BSアニマックス': '日本台', '日-J Sports': '体育', '釣りビジョン': '日本台',
        'フジテレビ': '日本台', '東映チャンネル': '日本台', 'チャンネルNECO': '日本台', 'ムービープラス': '日本台',
        'スカイA': '日本台', 'GAORA': '日本台', '日テレジータス': '日本台', 'ゴルフネットワーク': '日本台',
        '時代劇専門チャンネル': '日本台', 'ファミリー劇場': '日本台', 'ホームドラマチャンネル': '日本台',
        'チャンネル銀河': '日本台', 'スーパー!ドラマTV': '日本台', 'LaLaTV': '日本台', 'Music ON TV': '日本台',
        '歌謡ポップスチャンネル': '日本台', 'キッズステーション': '日本台', '日テレNEWS24': '日本台',
        '囲碁・将棋チャンネル': '日本台', 'Shop Channel': '日本台', 'MX Live': '日本台',
        'ウェザーニュース': '日本台', '群馬テレビ': '日本台', '漫步日本': '日本台',
        '东森': '港澳台', '超视美洲': '港澳台', 'ETtoday': '港澳台', '高点综合': '港澳台',
        '高点育乐': '港澳台',
        '年代新闻': '港澳台', '壹电视': '港澳台', '中天': '港澳台',
        '非凡新闻': '港澳台', '凤凰卫视': '港澳台', '凤凰新闻': '港澳台', '鳳凰衛視': '港澳台',
        '鳳凰新聞': '港澳台',
        '凤凰香港': '港澳台', '香港卫视': '港澳台',
        '凤凰资讯': '港澳台', '鳳凰資訊': '港澳台', '凤凰中文': '港澳台',
        '鳳凰中文': '港澳台', '香港开电视': '港澳台', '香港有線': '港澳台',
        '香港有线': '港澳台', '卫视合家欢': '港澳台', '衛視合家歡': '港澳台', 'HBO': '港澳台',
        'MYTV电影': '港澳台', 'MYTV電影': '港澳台', 'FRESH电影': '港澳台', 'FRESH電影': '港澳台',
        '非凡商业': '港澳台', '好莱坞电影': '港澳台', '亚洲旅游': '港澳台', '亚洲综合': '港澳台',
        '梅迪奇艺术': '港澳台', 'CINEMA影院': '港澳台',
        '博斯网球': '港澳台', '博斯无限': '港澳台', '香港國際': '港澳台', '香港国际': '港澳台',
        '星空卫视': '港澳台', '星空衛視': '港澳台', '翡翠台': '港澳台', '天映经典': '港澳台',
        '澳视': '港澳台', '澳視': '港澳台', '唯心台': '港澳台', 'ViuTV': '港澳台', 'Viutv': '港澳台',
        '功夫台': '港澳台',
        'ELEVEN體育': '港澳台', '星河台': '港澳台', '星河频道': '港澳台',
        '博斯运动': '港澳台', '龙祥': '港澳台', '龍祥': '港澳台', '明珠台': '港澳台', '凤凰频道': '港澳台',
        '鳳凰頻道': '港澳台', '港澳': '港澳台', '无线财经': '港澳台', '無線財經': '港澳台',
        'SMART知识': '港澳台', 'NHKWorld': '港澳台', 'FOX': '港澳台',
        'FoodNetwork': '港澳台', '纬来': '港澳台',
        '龙华动画': '港澳台', '龙华戏剧': '港澳台', '龙华偶像': '港澳台', '龙华电影': '港澳台',
        '龙华影剧': '港澳台', '国兴卫视': '港澳台', '國興衛視': '港澳台', '愛爾達': '港澳台',
        '爱尔达': '港澳台',
        '龙华洋片': '港澳台', '半岛新闻': '美利坚合众国',
        '龙华经典': '港澳台', 'ELEVEN体育': '体育', '亚洲旅游台': '港澳台', '亞洲旅遊台': '港澳台',
        '壹新聞': '港澳台', '华丽台': '港澳台',
        '靖洋': '港澳台', '靖天': '港澳台', '乐活频道': '港澳台', '视纳华仁': '港澳台', '采昌影剧': '港澳台',
        '华艺影剧': '港澳台', '华艺': '港澳台', '智林体育': '体育', 'Z频道': '港澳台',
        '新唐人': '港澳台', '大爱': '港澳台', '镜电视': '港澳台', '十方法界': '港澳台', '华藏卫星': '港澳台',
        '世界电视': '港澳台', '生命电视': '港澳台', '希望综合': '港澳台', '新天地民俗': '港澳台',
        '天美丽电视': '港澳台', '环宇新闻': '港澳台', '環宇新聞': '港澳台', '非凡新聞': '港澳台',
        'JET综合': '港澳台', 'JET綜合': '港澳台', '东风卫视': '港澳台', 'TVB无线': '港澳台',
        '東風衛視': '港澳台',
        '亚洲新闻': '港澳台', '有线新闻': '港澳台', '耀才财经': '港澳台', '有线财经': '港澳台',
        '正德电视': '港澳台', '双子卫视': '港澳台', '信大电视': '港澳台', '番薯卫星': '港澳台',
        '信吉艺文': '港澳台', '信吉卫星': '港澳台', '天良卫星': '港澳台', '大立电视': '港澳台',
        '诚心电视': '港澳台', '富立电视': '港澳台',
        '全大电视': '港澳台', '威达超舜': '港澳台', '海豚综合': '港澳台', '唯心电视': '港澳台',
        '冠军电视': '港澳台', '冠军梦想台': '港澳台', 'A-One体育': '体育', 'HOT频道': '港澳台',
        '彩虹E台': '港澳台', '澳亚卫视': '港澳台', '澳亞衛視': '港澳台',
        '彩虹电影': '港澳台', '松视': '港澳台', '惊艳成人电影台': '港澳台', '香蕉台': '港澳台',
        '美亚电影台': '港澳台',
        '好消息卫星': '港澳台', '好消息二台': '港澳台', '八大': '港澳台', '三立': '港澳台', 'TVBS': '港澳台',
        '台視': '港澳台', '中視': '港澳台', '國會頻道': '港澳台', '公視': '港澳台', 'HKIBC': '港澳台',
        '港台電視': '港澳台', '香港國際財經': '港澳台', 'J2台': '日本台',
        'Taiwan': '港澳台',
        '東森': '港澳台', '超視美洲': '港澳台', '高點綜合': '港澳台',
        '高點育樂': '港澳台', '年代新聞': '港澳台', '壹電視': '港澳台',
        '非凡商業': '港澳台', '亞洲旅遊': '港澳台', '亞洲綜合': '港澳台',
        'Medici-arts': '港澳台', '梅迪奇藝術': '港澳台', '博斯無限': '港澳台',
        'SMART知識': '港澳台', '龍華動畫': '港澳台',
        '龍華電影': '港澳台', '龍華影劇': '港澳台',
        '龍華經典': '港澳台',
        '樂活頻道': '港澳台', '視納華仁': '港澳台', '采昌影劇': '港澳台',
        '華藝影劇': '港澳台', '華藝': '港澳台', '智林體育': '港澳台', 'Z頻道': '港澳台',
        '鏡電視': '港澳台', '華藏衛星': '港澳台',
        '世界電視': '港澳台', '希望綜合': '港澳台', '天美麗電視': '港澳台',
        '正德電視': '港澳台', '雙子衛視': '港澳台', '番薯衛星': '港澳台',
        '信吉藝文': '港澳台', '信吉衛星': '港澳台', '天良衛星': '港澳台', '大立電視': '港澳台',
        '誠心電視': '港澳台', '富立電視': '港澳台',
        '全大電視': '港澳台', '威達超舜': '港澳台', '海豚綜合': '港澳台', '冠軍電視': '港澳台', '冠軍夢想台': '港澳台',
        'A-One體育': '港澳台', 'HOT頻道': '港澳台',
        'Hi-PLAY': '港澳台', '彩虹電影': '港澳台', '松視': '港澳台', '驚豔成人電影台': '港澳台',
        'Love Nature 4K': '港澳台', '美亞電影台': '港澳台',
        'LS TIME': '港澳台', '好消息衛星': '港澳台', 'MOMO': '港澳台',
        'iNEWS': '港澳台', 'MTV': '港澳台', '港澳台': '港澳台',
        '澳门': '港澳台', '澳門': '港澳台', '台灣': '港澳台', '国会频道': '港澳台', '公视': '港澳台',
        '凤凰': '港澳台',
        '上视': '港澳台', '台湾': '港澳台', '台视': '港澳台', '香港': '港澳台', '三台电视': '港澳台',
        '人間': '港澳台', '大愛電視': '港澳台', '緯來': '港澳台', '龍華戲劇台': '港澳台',
        '民视新闻': '港澳台', '东风37': '港澳台',
        '鳯凰': '港澳台', '天映': '港澳台', '亞旅': '港澳台', '八度空间': '港澳台', '华视': '港澳台',
        '民视': '港澳台', '中视': '港澳台', 'ELTA体育': '体育',
        '爱达': '港澳台', '波斯魅力台': '港澳台', '寰宇': '港澳台',
        '澳门莲花': '港澳台', '臺灣': '港澳台', '中国气象': '纪录片',
        '天才衝衝衝': '港澳台', '有线新闻台': '港澳台', '臺視': '港澳台', '博斯': '港澳台', '龙华': '港澳台',
        '龍華': '港澳台', '鳳凰': '港澳台', 'ELEVEN': '港澳台', 'eleven': '港澳台',
        '有線': '港澳台', '無綫': '港澳台', '全民最大党': '港澳台', '央視': '央视', '中央': '央视', '央视': '央视',
        'CCTV': '央视', 'cctv': '央视',
        '卫视': '卫视', '衛視': '卫视', 'CGTN': '央视', '环球电视': '央视',
        '华数': '华数', 'wasu.tv': '华数', '華數': '华数', 'CIBN': 'CIBN', '/cibn': 'CIBN', 'NewTv': 'NewTv',
        'NEWTV': 'NewTV', '/newtv': 'NewTV', '百視通': '百视通', '百事通': '百视通', 'BesTV': '百视通',
        'NewTV': 'NewTV', 'Cinevault 80': '美利坚合众国',
        'BESTV': '百视通', 'BestTv': '百视通', '/bestv': '百视通', '.bestv': '百视通', '百视通': '百视通',
        '新闻': '电视台', '体育': '体育', '动漫': '动漫', 'NASA': '科技', '豆瓣': '影视',
        '电影': '影视', '动画': '动画', '體育': '体育', '運動': '体育',
        '游戏风云': '游戏频道', '卡通': '卡通', '影院': '影视', '足球': '体育', '剧场': '剧场', '东方': '',
        '纪实': '纪录片', '电竞': '游戏频道', '教育': '教育', '自然': '自然', '动物': '自然', 'NATURE': '自然',
        '成龍': '明星', '成龙': '明星', '李连杰': '明星', '周星驰': '明星', '吴孟达': '明星', '刘德华': '明星',
        '周润发': '明星', '洪金宝': '明星', '黄渤': '明星', '林正英': '明星', '動畫': '动画',
        '七龍珠': '动漫', '海绵宝宝': '动漫', '猫和老鼠': '动漫',
        '网球王子': '动漫', '蜡笔小新': '动漫', '海贼王': '动漫', '中华小当家': '动漫', '四驱兄弟': '动漫',
        '哆啦A梦': '动漫', '樱桃小丸子': '动漫', '柯南': '动漫', '犬夜叉': '动漫', '乱马': '动漫', '童年': '',
        '高达': '动漫',
        '守护甜心': '动漫', '开心超人': '动漫', '开心宝贝': '动漫', '百变小樱': '动漫',
        '咱们裸熊': '动漫', '游戏王': '动漫',
        '三国演义': '剧场',
        '连续剧': '剧场', '音乐': '音乐', '綜合': '电视台',
        '财经': '电视台', '经济': '电视台', '美食': '美食', '资讯': '电视台', '旅游': '电视台',
        'Fashion4K': '时尚',
        '黑莓': '其他', '综艺': '电视台', '都市': '电视台', '看天下': '其他', '咪咕': '咪咕', '谍战': '剧场',
        '华语': '其他', '影视': '影视', '科教': '电视台', '生活': '电视台', 'discovery': '探索发现',
        '娱乐': '其他', '电视': '电视台', '纪录': '纪录片', '外语': '外语', '车迷': '时尚',
        '留学': '留学', '新闻频道': '电视台', '靓装': '时尚', '戏曲': '戏曲', '电视台': '电视台',
        '综合频道': '电视台',
        '综合': '电视台', '法制': '电视台', '数码': '电视台', '汽车': '时尚', '军旅': '影视', '古装': '影视',
        '喜剧': '影视', '惊悚': '影视', '悬疑': '影视',
        '科幻': '影视', '全球大片': '影视', '綜藝': '电视台',
        '咏春': '影视', '黑帮': '影视', '古墓': '影视',
        '警匪': '影视', '少儿': '少儿',
        '课堂': '教育', '政务': '电视台',
        '民生': '电视台', '农村': '电视台', '人文': '电视台', '幸福彩': '电视台',
        '新视觉': '科技', '金色频道': '其他',
        '新华英文': '国际', '垂钓': '体育', 'NHK WORLD': '国际',
        '时代': '其他', '休闲': '其他', 'ANN News FHD': '日本台',
        '兵器': '兵器', 'band news': '日本台',
        '纯享': '纪录片', 'ann_news': '日本台',
        'SiTV': '其他', 'CHC': '影视', 'nhk-hd': '国际',
        'BRTV': '其他', 'Lifetime': '其他', 'nhk hd': '国际',
        'GINX': '其他', 'Rollor': '其他', 'Generic': '国际',
        'GlobalTrekker': '其他', 'LUXE TV': '其他', 'Insight': '国际', 'Evenement': '其他',
        'Clarity': '美利坚合众国', 'hbo': '美利坚合众国',
        'TRAVELXP': '其他', 'ODISEA': '其他', 'MUZZIK': '其他', 'SKY HIGH': '美利坚合众国',
        'Liberty': '其他'
        }

dict_ennd = {}
for key, group in dict.items():
    dict_ennd[convert(key, 'zh-tw')] = group
    dict_ennd[convert(key, 'zh-cn')] = group

with open("/my_dict_file.txt", "w", encoding="utf-8") as f:
    json.dump(dict_ennd, f, ensure_ascii=False)

print(dict_ennd)