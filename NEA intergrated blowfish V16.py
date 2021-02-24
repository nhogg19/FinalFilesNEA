import sqlite3
from tkinter import *
import hashlib
import webbrowser
import random
from itertools import zip_longest
import string

root = Tk()
root.geometry("400x400")

class Elder:
    def __init__(self,master):
          self.main()
          self.show_hide = 1

    def main(self):
        root.geometry("400x400")
        self.main_frame = LabelFrame(root, text="Login / Register:", padx=20,pady=30)
        self.main_frame.grid(padx=30,pady=120)
        self.login_button=Button(self.main_frame, text="Login",width=20, height=2,command=self.btn_login).grid(row=0, column=0)
        self.register_button=Button(self.main_frame, text="Register",width=20,height=2,command=self.btn_register).grid(row=0, column=1)

    def main2(self):
        root.geometry("900x600")
        self.my_entrys_cred = []
        self.input_names_cred = ["Sitename:","Site URL:","Site Username:","Site Password:","Site Score:"]
        self.cred_frame = LabelFrame(root, text="Add / Update Site Info:", padx=20,pady=20)
        self.cred_frame.grid(padx=20,pady=20, column=0, row=0)
        for i in range(5):
            if i == 3:
                self.input_box_cred = Entry(self.cred_frame, width=30, show="*")
                self.my_entrys_cred.append(self.input_box_cred)
                self.input_box_cred.grid(row=i,column=1, pady=0,padx=5)
                label = Label(self.cred_frame, text=self.input_names_cred[i]).grid(row=i, column=0,padx=5,pady=5)
            else:
                self.input_box_cred = Entry(self.cred_frame, width=30)
                self.my_entrys_cred.append(self.input_box_cred)
                self.input_box_cred.grid(row=i,column=1, pady=0,padx=5)
                label = Label(self.cred_frame, text=self.input_names_cred[i]).grid(row=i, column=0,padx=5,pady=5)
                self.open_f=Button(self.cred_frame, text="Open",width=5, height=1,command=self.open_url).grid(row=1, column=3)
                self.copy_f=Button(self.cred_frame, text="Copy",width=5, height=1,command=self.copy).grid(row=3, column=3)
                self.check_f=Button(self.cred_frame, text="Check",width=5, height=1,command=self.check_strength_score).grid(row=4, column=3)

        self.store_f=Button(self.cred_frame, text="Store",width=25, height=1,command=self.store)
        self.store_f.grid(row=5, column=0,pady=0)
        self.clear_f=Button(self.cred_frame, text="Clear",width=25, height=1,command=self.clear)
        self.clear_f.grid(row=5, column=1,pady=0)

        self.cred_frame_select = LabelFrame(root, text="Select Site:", padx=20,pady=20)
        self.cred_frame_select.grid(padx=5,pady=20, column=1, row=0)
        self.view=Button(self.cred_frame_select, text="View",width=25, height=1,command=self.view)
        self.Delete_f=Button(self.cred_frame_select, text="Delete",width=5, height=1,command=self.delete)
        self.view.grid(row=2, column=0,padx=0,pady=5)
        self.Delete_f.grid(row=2, column=1,pady=5)

        self.scrollbar = Scrollbar(self.cred_frame_select)
        self.scrollbar.grid(column=1, row=0)
        self.site_list = Listbox(self.cred_frame_select, yscrollcommand = self.scrollbar.set, height=15, width=40)
        self.site_list.grid(column=0, row=0)

        self.scrollbar.config(command=self.site_list.yview)
        self.update_site_list()

        self.setting_frame = LabelFrame(root, text="Settings:", padx=20,pady=20)
        self.setting_frame.grid(padx=10,pady=10, column=1, row=2)

        self.logout_f=Button(self.setting_frame, text="Logout",width=25, height=1,command=self.logout)
        self.logout_f.grid(row=0, column=0)

        self.Generate_frame = LabelFrame(root, text="Generate Secure Password", padx=20,pady=20)
        self.Generate_frame.grid(padx=0,pady=0,row=1,column=1)
        self.label_gen = Entry(self.Generate_frame,width=22)
        self.label_gen.grid(row=2, column=0,padx=0,pady=5,columnspan=2)
        self.gen_copy=Button(self.Generate_frame, text="Copy",width=5, height=1,command=self.gen_copy)
        self.gen_copy.grid(row=1,column=1)
        self.gen_button=Button(self.Generate_frame, text="Generate",width=20, height=1,command=self.generate_password)
        self.gen_button.grid(row=1,column=0)



    def logout(self):
        self.cred_frame.destroy()
        self.setting_frame.destroy()
        self.cred_frame_select.destroy()
        self.Generate_frame.destroy()
        self.main()
        self.current_user_id = "0"
        pass

    def get_values_site_info(self):
        self.my_entrys_cred_contense = []
        for i in self.my_entrys_cred:
            self.my_entrys_cred_contense.append(i.get())

    def view(self):
        act = self.site_list.get(self.site_list.curselection())
        con = sqlite3.connect("mainoop.db")
        c = con.cursor()
        c.execute("SELECT Site_Name,Site_URL,Site_Username,Site_Password,Site_Strength_Score FROM Site_Info WHERE user_id ='{}' AND Site_Name = '{}'".format(
        self.current_user_id, act))
        con.commit()
        values_to_view = (c.fetchall()[0])
        for i, p in enumerate (self.my_entrys_cred):
            if i == 3:
                p.delete(0,END)
                dec = (self.DECRYPT(values_to_view[i],self.username)).replace(" ","")
                p.insert(0,dec)
                print(dec)
            else:
                p.delete(0,END)
                p.insert(0,values_to_view[i])

    def copy(self):
        self.get_values_site_info()
        coppied_value = self.my_entrys_cred_contense[3]
        root.clipboard_clear()
        root.clipboard_append(coppied_value)
        root.update()

    def check_strength_score(self):
        strength_score = 0
        self.my_entrys_cred[4].delete(0, END)
        self.get_values_site_info()
        passwrd = self.my_entrys_cred_contense[3]
        print("password = ", passwrd)
        length = len(passwrd)
        lower, upper, number, symbol, count = 0,0,0,0,0
        for i in passwrd:
            if i in string.ascii_lowercase:
                lower = 1    
            elif i in string.ascii_uppercase:
                upper = 1
            elif i in string.digits:
                number = 1
            elif i in string.punctuation:
                symbol = 1
            else:print("none")
        print(lower, upper, number, symbol)
        #####################
        if lower == 1:
            count += 26
        if upper == 1:
            count = count + 26
        if number == 1:
            count += 10
        if symbol == 1:
            count += 12
        combos = count ** length
        print(combos)
        ####################### calculates number of possible combinations
        complexity = lower + upper + number + symbol
        if length <= 6:
            length_score = 0
        if length == 7:
            length_score = 1
        if length >= 8 and length <= 9:
            length_score = 2
        if length >= 10:
            length_score = 3
        strength_score = complexity * length_score
        self.strength_score = (round(strength_score/1.2))
        self.my_entrys_cred[4].insert(0,self.strength_score)
        return(self.strength_score)


    def store(self):
        con = sqlite3.connect("mainoop.db")
        c = con.cursor()
        self.get_values_site_info()
        c.execute("SELECT Site_Name FROM Site_Info WHERE user_id = '{}' AND Site_Name = '{}'".format(self.current_user_id,self.my_entrys_cred_contense[0]))
        con.commit()
        result = (c.fetchone())
        if result != None:
            print("ERROR : Site with name,",self.my_entrys_cred_contense[0],"Already Exists")
        else:
            #encrypt password before storing 
            to_encrypt = self.my_entrys_cred_contense[3]
            print(to_encrypt)
            enc = self.ENCRYPT(to_encrypt,self.username)
            print(enc)
            interger_or_not = 1
            try:
                self.my_entrys_cred_contense[4] = int(self.my_entrys_cred_contense[4])
            except:
                interger_or_not = 0
                pass
            if interger_or_not == 1 and self.my_entrys_cred_contense[4] <= 10 and self.my_entrys_cred_contense[4] >= 0:
                score = self.my_entrys_cred_contense[4]
            else:
                score = self.check_strength_score()
            c.execute("INSERT INTO Site_Info (user_id,Site_Name,Site_URL,Site_Username,Site_Password,Site_Strength_Score) VALUES ('{}','{}','{}','{}','{}','{}')".format(
            self.current_user_id,self.my_entrys_cred_contense[0],self.my_entrys_cred_contense[1],
            self.my_entrys_cred_contense[2],enc,score))
            con.commit()
            self.clear()
            self.update_site_list()

    def update_site_list(self):
        con = sqlite3.connect("mainoop.db")
        c = con.cursor()
        self.get_values_site_info()
        c.execute("SELECT Site_Name FROM Site_Info WHERE user_id = '{}'".format(self.current_user_id))
        con.commit()
        results = (c.fetchall())
        self.site_list.delete(0,END)
        for i, p  in enumerate (results):
            self.site_list.insert(END,(p[0]))

    def delete(self):
        act = self.site_list.get(self.site_list.curselection())
        self.site_list.delete(ACTIVE)
        con = sqlite3.connect("mainoop.db")
        c = con.cursor()
        self.get_values_site_info()
        c.execute("DELETE FROM Site_Info WHERE user_id = '{}' AND Site_Name = '{}'".format(self.current_user_id,act))
        con.commit()

    def clear(self):
        for i in self.my_entrys_cred:
            i.delete(0,99)

    def open_url(self):
        try:
            self.get_values_site_info()
            value = self.my_entrys_cred_contense[1]
            if "://" not in value:
                print("Error : URL needs to be in form https://www.example.com")
            else:
                webbrowser.open((value))
        except:pass

    def btn_login(self):
        con = sqlite3.connect("mainoop.db")
        c = con.cursor()
        try:
            c.execute("""CREATE TABLE "Site_Info" (
           	"Credential_ID"	INTEGER,
           	"user_id"	INTEGER,
           	"Site_Name"	TEXT,
             "Site_URL"	TEXT,
           	"Site_Username"	TEXT,
           	"Site_Password"	TEXT,
             "Site_Strength_Score" TEXT,
           	PRIMARY KEY("Credential_ID")
             );""")
            con.commit()
        except:pass

        self.main_frame.destroy()
        self.login_frame = LabelFrame(root, text="Login:", padx=20,pady=5)
        self.login_frame.pack(padx=30,pady=125)
        submit=Button(self.login_frame, text="Submit",width=25, height=1,command=self.login_submit).grid(row=3, column=1,pady=5)
        submit2=Button(self.login_frame, text="Back",width=5, height=1,command=self.login_to_main).grid(row=3, column=0,pady=5)

        self.loginusername = Entry(self.login_frame, width=30)
        self.loginusername.grid(row=1, column=1)
        username_label = Label(self.login_frame, text="Username:")
        username_label.grid(row=1, column=0,padx=5,pady=5)

        self.loginpassword = Entry(self.login_frame, width=30,show="*")
        self.loginpassword.grid(row=2, column=1)
        password_label = Label(self.login_frame, text="Password:").grid(row=2, column=0,padx=5,pady=5)
        self.error_box1 = Label(self.login_frame, text="",width=40) #Error inserted message here
        self.error_box1.grid(row=4, column=0,columnspan=2)

    def btn_register(self):
        con = sqlite3.connect("mainoop.db")
        c = con.cursor()
        try:
            c.execute("""CREATE TABLE "Users" (
    	   "User_ID"	INTEGER,
    	   "Username"	TEXT,
    	   "Password"	TEXT,
    	   PRIMARY KEY("User_ID")
        );""")
            con.commit()
        except:pass

        self.my_entrys = []
        self.main_frame.destroy()
        self.input_names = ["Username:","Password:","Confirm Password:"]
        self.register_frame = LabelFrame(root, text="Register:", padx=20,pady=20)
        self.register_frame.pack(padx=30,pady=95)
        self.submit=Button(self.register_frame, text="Submit",width=25, height=1,command=self.register_submit)
        self.submit.grid(row=3, column=1,pady=5)
        self.submit2=Button(self.register_frame, text="Back",width=10, height=1,command=self.register_to_main)
        self.submit2.grid(row=3, column=0,pady=5)
        self.error_box2 = Label(self.register_frame, text="",width=30) #Error inserted message here
        self.error_box2.grid(row=4, column=0,columnspan=2)
        for i in range(3):
            if i>0:
                self.input_box = Entry(self.register_frame, width=30,show="*")
            else:
                self.input_box = Entry(self.register_frame, width=30)
            self.input_box.grid(row=i,column=1, pady=0,padx=5)
            self.my_entrys.append(self.input_box)
            label = Label(self.register_frame, text=self.input_names[i]).grid(row=i, column=0,padx=5,pady=5)


    def login_submit(self):
        self.L_username = self.loginusername.get()
        self.L_password = self.loginpassword.get()
        self.loginusername.delete(0,99)
        self.loginpassword.delete(0,99)
        hash_to_check = hashlib.sha256(self.L_password.encode()).hexdigest()
        con = sqlite3.connect("mainoop.db")
        c = con.cursor()
        c.execute("SELECT username, password FROM Users WHERE username = '{}' AND password = '{}'".format(self.L_username, hash_to_check))
        con.commit()
        result = (c.fetchone())
        if result == None:
            error = "Username / Password Incorrect"
            self.error_box1.config(text='{}'.format(error))
        else:
            error = "Authenicated"
            user_id = c.execute("SELECT User_ID FROM Users WHERE Username == '{}' and Password == '{}'".format(self.L_username, hash_to_check))
            con.commit()
            self.current_user_id = (user_id.fetchone()[0])
            self.current_username = c.execute("SELECT Username FROM Users WHERE User_ID == '{}' and Password == '{}'".format(self.current_user_id, hash_to_check))
            self.username = self.current_username.fetchone()[0]
            print(self.username)
            
            #print("user id =", self.current_user_id)
            self.error_box1.config(text='{}'.format(error))
            self.login_frame.destroy()
            self.main2()


    def generate_password(self):
        values = [chr(i) for i in range(127)][33:]
        list = (random.choices(values, k=20))
        self.generated = str(''.join(list))
        self.label_gen.insert(0,self.generated)

    def gen_copy(self):
        root.clipboard_clear()
        root.clipboard_append(self.generated)
        root.update()
        self.label_gen.delete(0,END)

    def register_submit(self):
        self.database_connect()
        self.word_entrys = []
        for i in self.my_entrys:
            self.word_entrys.append((str(i.get())))
            i.delete(0,99)

        con = sqlite3.connect("mainoop.db")
        c = con.cursor()

        error = ""
        self.username = self.word_entrys[0]
        hashed_password = hashlib.sha256(self.word_entrys[1].encode()).hexdigest()
        hashed_password_conf = hashlib.sha256(self.word_entrys[2].encode()).hexdigest()

        user_list = c.execute("SELECT Username FROM Users")
        con.commit()
        user_list = (c.fetchall())
        duplicate = 0
        for i in user_list:
            if self.username == i[0]:
                duplicate = 1
        if duplicate == 1:
            error = "User Account Already Exists"
            self.error_box2.config(text='{}'.format(error))
        else:
            if hashed_password == hashed_password_conf:
                c.execute("INSERT INTO Users(username, password) VALUES ('{}', '{}')".format(self.username, hashed_password))
                con.commit()

                #generate sub_keys and store them
                sub_keys, s_boxes = self.generate_sub_keys(self.word_entrys[1])
                flat_sub_keys = []
                for i in sub_keys:
                    flat_sub_keys.append(i)
                flat_s_boxes = (self.twoDtooneD(s_boxes))
                for x, y in zip_longest(flat_sub_keys, flat_s_boxes, fillvalue=""):
                    c.execute("INSERT INTO test (sub_keys,s_boxes,userid)VALUES (?, ?, ?) ",(x, y, self.username))
                con.commit()
                
                error = "Successful Account Creation Well Done"
                self.register_frame.destroy()
                self.btn_login()
            else: error = "Passwords Don't Match" + '\n'
            self.error_box2.config(text='{}'.format(error))

    def login_to_main(self):
        self.login_frame.destroy()
        self.main()
    def login_submit_two(self):
        pass
    def register_to_main(self):
        self.register_frame.destroy()
        self.main()

#########################################################################################################
    def database_connect(self):
        con = sqlite3.connect("mainoop.db")
        c = con.cursor()
        try: # test for storing users sub_keys & s_boxes
            c.execute("""CREATE TABLE "test" (
               "sub_keys"	TEXT,
               "s_boxes"	TEXT,
               "userid"     TEXT
            );""")
            con.commit()
        except:pass


    def str2bin(self,s, l):
        if l == 64:
            assert len(s) == 8, 'length of the string is not 64 bits'
        elif l == 32:
            assert len(s) == 4, 'length of the string is not 64 bits'

        return ''.join('{:08b}'.format(ord(i)) for i in s)


    def bin2hex(self,b):
        return ''.join('{:x}'.format(int(b[i:i + 4], 2)) for i in range(0, len(b), 4))


    def hex2bin(self,h):
        return ''.join('{:04b}'.format(int(i, 16)) for i in h)


    def bin2int(self,b):
        return int(b, 2)


    def bin2str(self,b):
        return ''.join(chr(int(b[i:i + 8], 2)) for i in range(0, len(b), 8))


    def hex2int(self,h):
        return int(h, 16)


    def _xor(self,a, b):
        assert type(a) == str and type(b) == str, 'there is something wrong with type in XOR'
        assert len(a) == 32 and len(b) == 32, 'lengths of blocks does not match to 64 in XOR'
        return ''.join(str(int(i) ^ int(j)) for i, j in zip(a, b))


    def _add(self,a, b):
        assert type(a) == str and type(b) == str, 'there is something wrong with type in ADD'
        assert len(a) == 32 and len(b) == 32, 'lengths of blocks does not match to 32 in ADD'
        return '{:032b}'.format((self.bin2int(a) + self.bin2int(b)) % (2**32))


    def _round(self,block, key, s_boxes):
        assert len(block) == 64, 'Error in round input, len of block is not 64 bits'
        assert len(key) == 32, 'length of key is not 64 bits'
        L, R = block[:len(block) // 2], block[len(block) // 2:]
        xored_L = self._xor(L, key)
        R_prime = xored_L

        L_split = [self.bin2int(xored_L[i:i + 8]) for i in range(0, len(xored_L), 8)]
        assert len(L_split) == 4, 'The splitted L has no 4 elements'
        s_values = [s_boxes[i][L_split[i]] for i in range(4)]

        assert len(s_values[0]) == 32, 's_values are not of 32 bits'

        # add1 -> xor1 -> add2
        result = self._add(s_values[3], self._xor(s_values[2], self._add(s_values[1], s_values[0])))

        assert len(result) == 32, 'output of s-boxes operation is not 32 bits'
        L_prime = self._xor(result, R)
        return L_prime + R_prime


    def encrypt(self,block, p_array, s_blocks):
        for key in p_array[:16]:
            block = self._round(block, key, s_blocks)

        left_block = block[:32]
        right_block = block[32:]
        right_block, left_block = left_block, right_block
        block = self._xor(p_array[17], left_block) + self._xor(p_array[16], right_block)
        return block


    def generate_sub_keys_origional(self,key):
        key = key * (72 // len(key)) + key
        key = key[:72]
        keys = [self.str2bin(key[i:i + 4], 32) for i in range(0, len(key), 4)]

        msg = '00000000'
        msg = self.str2bin(msg, 64)

        with open('test.txt', 'r') as f:
            P = [f.read(8) for i in range(18)]
            S = [[f.read(8) for j in range(256)] for k in range(4)]
            #print(P,S) #test this line can be removed

        P = [self.hex2bin(i) for i in P]
        for i in range(4):
            for j in range(256):
                S[i][j] = self.hex2bin(S[i][j])

        P = [self._xor(keys[i], P[i]) for i in range(18)]

        for i in range(0, len(P), 2):
            msg = self.encrypt(msg, P, S)
            P[i] = msg[:32]
            P[i + 1] = msg[32:]

        for i in range(4):
            for j in range(0, 256, 2):
                msg = self.encrypt(msg, P, S)
                S[i][j] = msg[:32]
                S[i][j + 1] = msg[32:]


    def generate_sub_keys(self,key):
        key = key * (72 // len(key)) + key
        key = key[:72]
        keys = [self.str2bin(key[i:i + 4], 32) for i in range(0, len(key), 4)]

        msg = '00000000'
        msg = self.str2bin(msg, 64)
        
        with open('test.txt', 'r') as f:
            P = [f.read(8) for i in range(18)]
            S = [[f.read(8) for j in range(256)]for k in range(4)]

        P = [self.hex2bin(i) for i in P]
        for i in range(4):
            for j in range(256):
                S[i][j] = self.hex2bin(S[i][j])

        P = [self._xor(keys[i], P[i]) for i in range(18)]

        for i in range(0, len(P), 2):
            msg = self.encrypt(msg, P, S)
            P[i] = msg[:32]
            P[i + 1] = msg[32:]

        for i in range(4):
            for j in range(0, 256, 2):
                msg = self.encrypt(msg, P, S)
                S[i][j] = msg[:32]
                S[i][j + 1] = msg[32:]

        return P, S


    def encryption(self,msg, sub_keys, s_boxes, mode):
        if mode == 'e':
            msg = [msg[i:i + 8] for i in range(0, len(msg), 8)]
            if len(msg[-1]) < 8:
                msg[-1] += ' ' * (8 - len(msg[-1]))

            msg = [self.str2bin(i, None) for i in msg]

        elif mode == 'd':
            msg = [self.hex2bin(msg[i:i + 16]) for i in range(0, len(msg), 16)]

        ciphertext = ''
        for each in msg:
            ciphertext += self.encrypt(each, sub_keys, s_boxes)

        if mode == 'e':
            cipher = self.bin2hex(ciphertext)

        if mode == 'd':
            cipher = self.bin2str(ciphertext)

        return cipher


    def twoDtooneD(self,box): #converting 2D list to 1D so that can be stored in database
        listt = []
        for i in box:
            for p in i:
                listt.append(p)
        return(listt)

    def oneDtotwoD(self,l, n): #converting 1D to 2D so database info can be used in the encryption
        return [l[i:i+n] for i in range(0, len(l), n)]

    def ENCRYPT(self,message,userid):
        con = sqlite3.connect("mainoop.db")
        c = con.cursor()
        #CHUNK OF CODE - GETS KEYS FROM DATABASE - can removed duplicate when using classes ############
        result_sub_keys = c.execute("SELECT sub_keys FROM test WHERE userid == '{}'".format(userid))
        result_sub_keys = [x[0] for x in result_sub_keys][:18]
        #print(sub_keys) #print to prove they match
        #print(result_sub_keys) #print to prove they match
                
        result_s_boxes = c.execute("SELECT s_boxes FROM test WHERE userid == '{}'".format(userid))
        result_s_boxes = c.fetchall()
        new_res = []
        for i in result_s_boxes:
            a = i[0]
            new_res.append(a)
        result_s_boxes = self.oneDtotwoD(new_res,256)
        print(result_s_boxes)
        print(result_sub_keys) ######## Then encryptes
        enc = self.encryption(message, result_sub_keys, result_s_boxes, 'e')
        print('encrypted message:', enc)
        return(enc)
        ################################################################################################
        #CHUNK OF CODE - GETS KEYS FROM DATABASE #####################################################
        con = sqlite3.connect("mainoop.db")
        c = con.cursor()
        result_sub_keys = c.execute("SELECT sub_keys FROM test WHERE userid == '{}'".format(userid))
        result_sub_keys = [x[0] for x in result_sub_keys][:18]
        #print(sub_keys) #print to prove they match
        #print(result_sub_keys) #print to prove they match
            
        result_s_boxes = c.execute("SELECT s_boxes FROM test WHERE userid == '{}'".format(userid))
        result_s_boxes = c.fetchall()
        new_res = []
        for i in result_s_boxes:
            a = i[0]
            new_res.append(a)
        result_s_boxes = oneDtotwoD(new_res,256)
        enc = encryption(message, result_sub_keys, result_s_boxes, 'e')
        return(enc)
            ################################################################################################
        
            #else:
                #print("error user subs already in")################################# DUPLICATE CODE NEEDS TO BE MADE SMOTHER
                #else get keys and sbox from database to be used in encryption process
                #result_sub_keys = c.execute("SELECT sub_keys FROM test WHERE userid == '{}'".format(userid))
                #result_sub_keys = [x[0] for x in result_sub_keys][:18]
                ##print(sub_keys) #print to prove they match
                ##print(result_sub_keys) #print to prove they match

                #result_s_boxes = c.execute("SELECT s_boxes FROM test WHERE userid == '{}'".format(userid))
                #result_s_boxes = c.fetchall()
                #new_res = []
                #for i in result_s_boxes:
                #    a = i[0]
                #    new_res.append(a)
                #result_s_boxes = oneDtotwoD(new_res,256)
                ##print (s_boxes) #print to prove they match
                ##print(result_s_boxes) #print to prove they match
                #enc = encryption(messages, result_sub_keys, result_s_boxes, 'e')
                #print('encrypted message:', enc)
                #return(enc)
     ###########################################################################
        
    def DECRYPT(self,enc,userid):
        con = sqlite3.connect("mainoop.db")
        c = con.cursor()
        #else get keys and sbox from database to be used in encryption process
        result_sub_keys = c.execute("SELECT sub_keys FROM test WHERE userid == '{}'".format(userid))
        result_sub_keys = [x[0] for x in result_sub_keys][:18]
        #print(sub_keys) #print to prove they match
        #print(result_sub_keys) #print to prove they match

        result_s_boxes = c.execute("SELECT s_boxes FROM test WHERE userid == '{}'".format(userid))
        result_s_boxes = c.fetchall()
        new_res = []
        for i in result_s_boxes:
            a = i[0]
            new_res.append(a)
        result_s_boxes = self.oneDtotwoD(new_res,256)
        #print (s_boxes) #print to prove they match
        #print(result_s_boxes) #print to prove they match

        dec = self.encryption(enc, result_sub_keys[::-1], result_s_boxes, 'd')
        print('decrypted message:',dec)
        return(dec)


e = Elder(root)

root.mainloop()
