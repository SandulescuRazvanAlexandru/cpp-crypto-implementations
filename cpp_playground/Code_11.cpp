#include <string>
#include <iostream>
using namespace std;

class Student
{
private:
	int age;
	char* name;
public:
	Student();	// default constructor
	Student(int v, char* n); // constructor with params
	Student(Student&);	// copy constructor

	void operator=(Student&); // overload the assignment operator (=)

	~Student(); // destructor mandatory to be in this class (name is allocated in heap mem)

	char* getName() {
		return this->name;
	}

	void changeName() {
		if (this->name != NULL) 
			this->name[0] = 'Y';
	}
};

Student::Student() {
	cout<<" Default constructor."<<endl;
	this->age = 0;
	this->name = NULL;
}

Student::Student(int v, char* n) {
	cout<<" Constructor with parameters."<<endl;
	this->age = v;
	if (n != NULL) {
		this->name = new char[strlen(n)+1];
		strcpy(this->name, n);
	} else this->name = NULL;
}

Student::Student(Student& obr) {
	cout<<" Copy constructor."<<endl;
	this->age = obr.age;
	if (obr.name != NULL) {
		this->name = new char[strlen(obr.name) + 1];
		strcpy(this->name, obr.name);
	} else this->name = NULL;
}

Student::~Student() {
	cout<<" Destructor."<<endl;
	if (this->name != NULL)
		delete[] this->name;
}

void Student::operator =(Student& obr) {
	cout<<"Operator ="<<endl;
	this->age = obr.age;
	if (obr.name != NULL) {
		if(this->name != NULL) delete[] this->name;
		this->name = new char[strlen(obr.name) + 1];
		strcpy(this->name, obr.name);
	} else {
		if(this->name != NULL) delete[] this->name;
		this->name = NULL;
	}
}

int main() 
{
	Student x; // default constructor
	// {
	int age1 = 21; int age2 = 20;
	char* name1 = (char*)"John"; char* name2 = (char*)"Smith";

	Student s1(age1, name1); // constructor with parameters
	Student s2(age2, name2); // constructor with parameters
	Student s3 = s1;// Student s3(s1); // copy constructor
	Student s4; // default constructor

	// while (1) {
		s4 = s2; // overloaded version of operator = is called

		cout<<"Name s1: "<<s1.getName()<<", Name s2: "<<s2.getName()<<", Name s3: "<<s3.getName()<<
			", Name s4: "<<s4.getName()<<endl;
		s3.changeName();	
		cout<<"Name s1: "<<s1.getName()<<", Name s2: "<<s2.getName()<<", Name s3: "<<s3.getName()<<
			", Name s4: "<<s4.getName()<<endl;
	// }
	// }
	cout<<"End of application!"<<endl;

	return 0;
}
