
Bu layihə, verilmiş server log faylını analiz edərək uğursuz giriş cəhdlərini və təhlükəli IP-ləri müəyyən etmək üçün hazırlanmışdır. Layihə Python dilində yazılıb və əsasən Regex (regular expressions) və fayl manipulyasiyasından istifadə edir.

## Ardıcıllıq

1. **Layihəni yükləyin:**   
   GitHub-da layihə səhifənizdən layihəni yükləyin:
   ```bash
   git clone https://github.com/Nuranss/LAB1.git
   cd lab1
2. **Virtual mühit yaradın və aktivləşdirin:**   
   Layihənin asılılıqlarını izolyasiya etmək üçün virtual mühit yaradın:
   python -m venv venv
   venv\Scripts\activate  # Windows üçün
3. **Kitabxanaları quraşdırın:**   
   Layihənin işləməsi üçün lazım olan kitabxanaları requirements.txt faylından quraşdırın:
   pip freeze > requirements.txt
   python -m pip install --upgrade pip
   pip install -r requirements.txt
4. **Skripti işə salın:**   
   Log faylını analiz etmək üçün aşağıdakı əmri icra edin:
   python main.py   

Layihə Strukturunun Təsviri   
main.py: Log faylının analizi və nəticələrin çıxarılması üçün əsas Python skripti.   
server_logs.txt: Log faylı. Bu fayl analiz etmək üçün istifadə olunur.   
question.txt: Tapşırıq sualları və tapşırıq detalları.   
requirements.txt: Layihənin işləməsi üçün lazım olan kitabxanalar.   
failed_logins.json: 5-dən çox uğursuz giriş cəhdi olan IP-lərin siyahısı.   
threat_ips.json: Təhlükəli IP-lərin siyahısı.   
combined_security_data.json: Uğursuz girişlər və təhlükəli IP-lərini birləşdirən fayl.   
log_analysis.txt: Log analizinin nəticələrinin mətn faylı.   
log_analysis.csv: Log məlumatlarının cədvəl formatında saxlanması.   

Texnologiyalar   
Python 3.8+   
Regex: Loglardan məlumat çıxarmaq üçün.   

Əlaqə:   
Əgər hər hansı bir sualınız varsa, mənimlə əlaqə saxlaya bilərsiniz: nuransgrov@gmail.com
