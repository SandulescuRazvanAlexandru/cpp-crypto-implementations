#include <stdio.h>
#include <malloc.h>
#include <string.h>

struct Book
{
	int isbn;
	float price;
};

struct Node
{
	Node* leftSubT;
	Book* bookRef;
	Node* rightSubT;
};

Node* createNode(Book* aBook, Node* sLeft, Node* sRight) {
	Node* newNode = (Node*)malloc(1 * sizeof(Node));
	newNode->bookRef = aBook;
	newNode->leftSubT = sLeft;
	newNode->rightSubT = sRight;
	return newNode;
}

Node* addNode(Node* root, Book* aBook) {
	Node* aux = NULL;
	if (!root) {
		return createNode(aBook, NULL, NULL);
	} else {
		aux = root;
		while(1) {
			if (aBook->isbn < root->bookRef->isbn) {
				if (root->leftSubT) {
					root = root->leftSubT;
				} else {
					root->leftSubT = createNode(aBook, NULL, NULL);
					return aux;
				}
			} else {
				if (aBook->isbn > root->bookRef->isbn) {
					if (root->rightSubT) {
						root = root->rightSubT;
					} else {
						root->rightSubT = createNode(aBook, NULL, NULL);
						return aux;
					}
				} else {
					//node is already in tree
					return aux;
				}
			}
		} //end while
	} //end else if(!root)
} //end addNode

void LRR_BinaryTreeParser(Node* r) {
	if (r) {
		LRR_BinaryTreeParser(r->leftSubT);
		// LRR_BinaryTreeParser(r);
		printf("\n isbn = %d, price = %f", r->bookRef->isbn, r->bookRef->price);
		LRR_BinaryTreeParser(r->rightSubT);
	}
}

Node* search(int isbnFinder, Node* r) {
	Node* aux = NULL;
	if (!r) return aux;
	while (1) {
		if(isbnFinder < r->bookRef->isbn) {
			if (r->leftSubT) r = r->leftSubT;
			else return aux;
		} else {
			if (isbnFinder > r->bookRef->isbn) {
				if (r->rightSubT) r = r->rightSubT;
				else return aux;
			} else {
				aux = r;
				return aux;
			}
		}
	}
}

int main()
{
	Node* treeRoot = NULL;
	Book* bookItem = NULL;
	int isbnFind = 0;
	Node* foundNode = NULL;

	bookItem = (Book*)malloc(1 * sizeof(Book));
	printf("isbn = "); scanf("%d", &bookItem->isbn);
	while(bookItem->isbn != 0) {
		printf("price = "); scanf("%f", &bookItem->price);

		treeRoot = addNode(treeRoot, bookItem);

		bookItem = (Book*)malloc(1 * sizeof(Book));
		printf("isbn = "); scanf("%d", &bookItem->isbn);
	}

	LRR_BinaryTreeParser(treeRoot);

	printf("\n isbn to search="); scanf("%d", &isbnFind);
	
	foundNode = search(isbnFind, treeRoot);
	
	if (foundNode) 
		printf("\n found isbn =%d, found price =%f",foundNode->bookRef->isbn, foundNode->bookRef->price);
	else 
		printf("\n node was not found!");

	return 0;
}