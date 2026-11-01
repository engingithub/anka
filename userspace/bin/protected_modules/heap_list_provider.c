struct Node{int value;struct Node *next;};
struct Node *identity(struct Node *p){return p;}
int total(struct Node *p){return p->value+p->next->value;}
