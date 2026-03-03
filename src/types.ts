export type Session = {
	id: string;
	userId: string;
	accessToken: string;
	refreshToken: string | null;
	tokenType: string;
	expiresOn: Date | null;
	scopes: string | null;
	state: string | null;
};

export type User = {
	id: string;
	name: string | null;
	email: string;
	department: string | null;
	roles: string | null;
	keystoneInitials: string | null;
	dateCreated: Date;
	dateUpdated: Date | null;
};
