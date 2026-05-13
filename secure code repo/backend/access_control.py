class AccessControl:
    """Access Control List (ACL) Implementation"""
    
    # Access Control Matrix Definition
    ROLES = {
        'Owner': {'can_read': True, 'can_write': True, 'can_delete': True},
        'Collaborator': {'can_read': True, 'can_write': True, 'can_delete': False},
        'Viewer': {'can_read': True, 'can_write': False, 'can_delete': False}
    }
    
    def __init__(self, db):
        self.db = db
    
    def grant_access(self, user_id, repo_id, role):
        """Grant access to a user for a repository"""
        if role not in self.ROLES:
            return False, "Invalid role"
        
        permissions = self.ROLES[role]
        cursor = self.db.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO access_control 
                (user_id, repo_id, role, can_read, can_write, can_delete)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, repo_id, role, 
                  permissions['can_read'], 
                  permissions['can_write'], 
                  permissions['can_delete']))
            
            self.db.commit()
            return True, f"Access granted as {role}"
        except Exception as e:
            return False, str(e)
    
    def check_permission(self, user_id, repo_id, permission_type):
        """Check if user has specific permission on repository
        permission_type: 'can_read', 'can_write', 'can_delete'
        """
        cursor = self.db.cursor()
        
        cursor.execute(f"""
            SELECT {permission_type} FROM access_control
            WHERE user_id = ? AND repo_id = ?
        """, (user_id, repo_id))
        
        result = cursor.fetchone()
        if result and result[0] == 1:
            return True
        return False
    
    def get_user_role(self, user_id, repo_id):
        """Get user's role for a repository"""
        cursor = self.db.cursor()
        
        cursor.execute("""
            SELECT role FROM access_control
            WHERE user_id = ? AND repo_id = ?
        """, (user_id, repo_id))
        
        result = cursor.fetchone()
        return result[0] if result else None
    
    def list_user_repositories(self, user_id):
        """List all repositories user has access to"""
        cursor = self.db.cursor()
        
        cursor.execute("""
            SELECT r.repo_id, r.repo_name, ac.role, r.description
            FROM repositories r
            JOIN access_control ac ON r.repo_id = ac.repo_id
            WHERE ac.user_id = ?
        """, (user_id,))
        
        return cursor.fetchall()
    
    def revoke_access(self, user_id, repo_id):
        """Revoke user's access to repository"""
        cursor = self.db.cursor()
        cursor.execute("""
            DELETE FROM access_control
            WHERE user_id = ? AND repo_id = ?
        """, (user_id, repo_id))
        self.db.commit()

    def get_repo_users(self, repo_id):
        """Get all users with access to a repository"""
        cursor = self.db.cursor()
        
        cursor.execute("""
            SELECT u.username, ac.role
            FROM access_control ac
            JOIN users u ON ac.user_id = u.user_id
            WHERE ac.repo_id = ?
            ORDER BY 
                CASE role
                    WHEN 'Owner' THEN 1
                    WHEN 'Collaborator' THEN 2
                    WHEN 'Viewer' THEN 3
                    ELSE 4
                END
        """, (repo_id,))
        
        return cursor.fetchall()